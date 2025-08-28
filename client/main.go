package main

import (
    "bufio"
    "encoding/binary"
    "flag"
    "fmt"
    "net"
    "os"
    "time"
    
    "e2eproto/common"
)

const defaultAddr = "127.0.0.1:8000"

func main() {
    mode := flag.String("mode", "exec", "exec | upload")
    addr := flag.String("addr", defaultAddr, "host:port")

    clientPriv := flag.String("client-priv", "client_priv.bin", "arquivo da chave privada do cliente")
    clientPub := flag.String("client-pub", "client_pub.bin", "arquivo da chave pública do cliente")
    serverPubPath := flag.String("server-pub", "server_pub.bin", "arquivo da pub do servidor")

    sync := flag.Bool("sync", false, "executa HELLO, recebe e salva server_pub")
    reset := flag.Bool("reset", false, "pede para o servidor esquecer a key do cliente e desconectar")

    cmd := flag.String("cmd", "", "comando shell remoto")
    timeout := flag.Uint("timeout", 30, "timeout em segundos para exec")

    file := flag.String("file", "", "arquivo local para enviar")
    path := flag.String("path", "", "caminho remoto alvo")

    flag.Parse()

    cliKP, err := common.LoadOrCreateKeypair(*clientPriv, *clientPub)
    failErr(err)

    if *sync {
        conn, err := net.Dial("tcp", *addr)
        failErr(err)
        defer conn.Close()

        failErr(common.WriteHello(conn, &cliKP.Public))

        _ = conn.SetReadDeadline(time.Now().Add(common.ReadDeadline))
        srvPub, err := common.ReadHelloReply(conn)
        failErr(err)

        failErr(common.SavePubKey(*serverPubPath, srvPub))
        fmt.Println("sincronizado: server_pub salvo em", *serverPubPath)

        return
    }

    if *reset {
        conn, err := net.Dial("tcp", *addr)
        failErr(err)
        defer conn.Close()

        failErr(common.WriteReset(conn, &cliKP.Public))

        _ = conn.SetReadDeadline(time.Now().Add(common.ReadDeadline))
        line, err := bufio.NewReader(conn).ReadString('\n')
        failErr(err)
        fmt.Print("server: ", line)

        return
    }

    srvPub, err := common.LoadPubKey(*serverPubPath)
    failErr(err)

    conn, err := net.Dial("tcp", *addr)
    failErr(err)
    defer conn.Close()

    switch *mode {
    case "exec":
        if *cmd == "" {
            fail("use -cmd com mode=exec")
        }

        doExec(conn, srvPub, cliKP, *cmd, uint32(*timeout))
    case "upload":
        if *file == "" || *path == "" {
            fail("use -file e -path com mode=upload")
        }

        doUpload(conn, srvPub, cliKP, *file, *path)
    default:
        fail("mode inválido")
    }
}

func doExec(conn net.Conn, srvPub *[common.PubKeySize]byte, cli *common.KeyPair, command string, timeoutSec uint32) {
    pt := common.MarshalExecPayload(command, timeoutSec)
    _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
    failErr(common.WriteEncryptedFrame(conn, common.CmdExecRaw, &cli.Public, srvPub, pt))

    _ = conn.SetReadDeadline(time.Now().Add(common.ReadDeadline))
    op, senderStatic, senderEph, nonce, cipher, err := common.ReadEncryptedFrame(conn)
    failErr(err)
    if op != common.CmdExecRaw {
        fail("opcode de resposta inesperado")
    }

    _ = senderStatic
    plain, err := common.BoxDecrypt(&cli.Private, &senderEph, &nonce, cipher)
    failErr(err)
    if len(plain) < 12 {
        fail("exec reply curto")
    }

    exit := binary.LittleEndian.Uint32(plain[0:4])
    outLen := binary.LittleEndian.Uint64(plain[4:12])
    if uint64(len(plain)) != 12+outLen {
        fail("exec reply malformado")
    }

    out := plain[12:]
    fmt.Printf("exit=%d\n", exit)
    os.Stdout.Write(out)
    if len(out) == 0 || out[len(out)-1] != '\n' {
        fmt.Println()
    }
}

func doUpload(conn net.Conn, srvPub *[common.PubKeySize]byte, cli *common.KeyPair, local, remote string) {
    data, err := os.ReadFile(local)
    failErr(err)
    pt := common.MarshalUploadPayload(remote, data)

    _ = conn.SetWriteDeadline(time.Now().Add(common.WriteDeadline))
    failErr(common.WriteEncryptedFrame(conn, common.UploadFile, &cli.Public, srvPub, pt))

    _ = conn.SetReadDeadline(time.Now().Add(common.ReadDeadline))
    op, senderStatic, senderEph, nonce, cipher, err := common.ReadEncryptedFrame(conn)
    failErr(err)
    if op != common.UploadFile {
        fail("opcode de resposta inesperado")
    }

    _ = senderStatic
    plain, err := common.BoxDecrypt(&cli.Private, &senderEph, &nonce, cipher)
    failErr(err)
    os.Stdout.Write(plain)
    if len(plain) == 0 || plain[len(plain)-1] != '\n' {
        fmt.Println()
    }
}

func fail(msg string) {
    fmt.Fprintln(os.Stderr, msg)
    os.Exit(2)
}

func failErr(err error) {
    if err != nil {
        fmt.Fprintln(os.Stderr, "error:", err)
        os.Exit(1)
    }
}

