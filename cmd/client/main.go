package main

import (
    "bufio"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    
    p "gungnir/internal/proto"
)

type Client struct {
    id   string
    conn net.Conn
    r    *bufio.Reader
    send chan *p.Message
    wg   sync.WaitGroup
}

func main() {
    server := flag.String("server", "127.0.0.1:9000", "server tcp address host:port")
    id := flag.String("id", "", "client id, default hostname")
    flag.Parse()

    if *id == "" {
        *id = hostnameFallback()
    }

    conn, err := net.Dial("tcp", *server)
    if err != nil {
        log.Fatalf("connect failed: %v", err)
    }
    defer conn.Close()

    c := &Client{
        id:   *id,
        conn: conn,
        r:    bufio.NewReader(conn),
        send: make(chan *p.Message, 32),
    }

    // writer
    c.wg.Add(1)
    go func() {
        defer c.wg.Done()
        for msg := range c.send {
            if err := p.WriteJSON(conn, msg); err != nil {
                log.Printf("write error: %v", err)
                return
            }
        }
    }()

    // register
    if err := p.WriteJSON(conn, &p.Message{Type: "register", ClientID: c.id}); err != nil {
        log.Fatalf("register failed: %v", err)
    }

    log.Printf("connected as %s to %s", c.id, *server)

    // reader loop
    for {
        var msg p.Message
        if err := p.ReadJSON(c.r, &msg); err != nil {
            if errors.Is(err, io.EOF) {
                log.Printf("server closed")
                break
            }

            log.Fatalf("read error: %v", err)
        }
        switch msg.Type {
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
        Type:     "file",     // pull_file response
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

