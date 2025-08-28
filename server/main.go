package main

import (
    "bufio"
    "context"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "io"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "time"
    
    "e2eproto/common"
    "golang.org/x/crypto/nacl/box"
)

const (
    maxCmdLenPlain  = 1 << 20
    maxExecOutBytes = 10 << 20
    maxPathLen      = 4096
    maxUploadBytes  = 64 << 20
    defaultTimeout  = 30
    hardCapTimeout  = 600
)

type connState struct {
    // filled in when the session says HELLO; not required to respond,
    // since each encrypted frame contains the senderStaticPub
    clientPub *[common.PubKeySize]byte
}

func main() {
    // generates server pair only in memory
    serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
    must(err)

    port, ln, err := common.GetFreePortInRange("0.0.0.0", 4000, 9000)
    must(err)
    fmt.Println("listening at", port)

    // memory of known clients
    known := make(map[[common.PubKeySize]byte]struct{})

    for {
        c, err := ln.Accept()
        if err != nil {
            fmt.Println("accept:", err)
            continue
        }

        go handle(c, serverPub, serverPriv, known)
    }
}

func handle(conn net.Conn, serverPub, serverPriv *[common.PubKeySize]byte, known map[[common.PubKeySize]byte]struct{}) {
    defer conn.Close()
    r := bufio.NewReader(conn)
    state := &connState{}

    for {
        _ = conn.SetReadDeadline(time.Now().Add(common.ReadDeadline))

        // checks the first byte to decide whether it is plain (HELLO/RESET) or an encrypted frame
        bt, err := r.Peek(1)
        if err != nil {
          if err != io.EOF {
              fmt.Println("peek:", err)
          }

          return
        }

        op := bt[0]
        switch op {
        case common.OpHello:
            _, _ = r.ReadByte()
            cpub, err := common.ReadHello(r)
            if err != nil {
                fmt.Println("hello err:", err)
                return
            }

            state.clientPub = cpub
            known[*cpub] = struct{}{}
            _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
            if err := common.WriteHelloReply(conn, serverPub); err != nil {
                fmt.Println("hello reply err:", err)
                return
            }

            continue
        case common.OpReset:
            _, _ = r.ReadByte()
            var cpub [common.PubKeySize]byte
            if _, err := io.ReadFull(r, cpub[:]); err != nil {
                fmt.Println("reset read:", err)
                return
            }

            delete(known, cpub)

            _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
            _, _ = conn.Write([]byte("LOGGED_OUT\n"))
            return
        default:
            // it is a complete encrypted frame; use the direct reader
            opc, senderStatic, senderEph, nonce, cipher, err := common.ReadEncryptedFrame(r)
            if err != nil {
                fmt.Println("read frame:", err)
                return
            }

            plain, err := common.BoxDecrypt(serverPriv, &senderEph, &nonce, cipher)
            if err != nil {
                fmt.Println("decrypt:", err)
                return
            }

            switch opc {
            case common.CmdExecRaw:
                if err := handleExecPlain(conn, serverPub, &senderStatic, plain); err != nil {
                    fmt.Println("exec error:", err)
                    return
                }
            case common.UploadFile:
                if err := handleUploadPlain(conn, serverPub, &senderStatic, plain); err != nil {
                    fmt.Println("upload error:", err)
                    return
                }
            default:
                sendEncryptedLine(conn, serverPub, &senderStatic, []byte("UNKNOWN_COMMAND\n"), common.UploadFile)
            }
        }
    }
}

func handleExecPlain(conn net.Conn, serverPub, replyTo *[common.PubKeySize]byte, plain []byte) error {
    cmdStr, timeoutSec, err := common.UnmarshalExecPayload(plain)
    if err != nil {
        return sendEncryptedLine(conn, serverPub, replyTo, []byte("ERR "+err.Error()+"\n"), common.CmdExecRaw)
    }

    if len(cmdStr) == 0 || len(cmdStr) > maxCmdLenPlain {
        return sendEncryptedLine(conn, serverPub, replyTo, []byte("ERR invalid cmd length\n"), common.CmdExecRaw)
    }

    if timeoutSec == 0 {
        timeoutSec = defaultTimeout
    }

    if timeoutSec > hardCapTimeout {
        timeoutSec = hardCapTimeout
    }

    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
    out, err := cmd.CombinedOutput()
    if len(out) > maxExecOutBytes {
        out = append(out[:maxExecOutBytes], []byte("\n...[truncated]")...)
    }

    var exit uint32
    if err != nil {
        if ee, ok := err.(*exec.ExitError); ok {
            exit = uint32(ee.ExitCode())
        } else if ctx.Err() == context.DeadlineExceeded {
            exit = 124
            out = append(out, []byte("\n[timeout]")...)
        } else {
            exit = 0xFFFFFFFF
        }
    }

    resp := make([]byte, 12+len(out))
    binary.LittleEndian.PutUint32(resp[0:4], exit)
    binary.LittleEndian.PutUint64(resp[4:12], uint64(len(out)))
    copy(resp[12:], out)

    _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
    return common.WriteEncryptedFrame(conn, common.CmdExecRaw, serverPub, replyTo, resp)
}

func handleUploadPlain(conn net.Conn, serverPub, replyTo *[common.PubKeySize]byte, plain []byte) error {
    path, body, err := common.UnmarshalUploadPayload(plain, maxPathLen, maxUploadBytes)
    if err != nil {
        return sendEncryptedLine(conn, serverPub, replyTo, []byte("ERR "+err.Error()+"\n"), common.UploadFile)
    }

    dir := filepath.Dir(path)
    if dir != "" && dir != "." {
        if err := os.MkdirAll(dir, 0o755); err != nil {
            return sendEncryptedLine(conn, serverPub, replyTo, []byte("ERR mkdir\n"), common.UploadFile)
        }
    }

    if err := os.WriteFile(path, body, 0o644); err != nil {
        return sendEncryptedLine(conn, serverPub, replyTo, []byte("ERR write file\n"), common.UploadFile)
    }

    return sendEncryptedLine(conn, serverPub, replyTo, []byte("OK\n"), common.UploadFile)
}

func sendEncryptedLine(conn net.Conn, serverPub, replyTo *[common.PubKeySize]byte, line []byte, opcode byte) error {
    _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
    return common.WriteEncryptedFrame(conn, opcode, serverPub, replyTo, line)
}

func must(err error) {
    if err != nil {
        panic(err)
    }
}

