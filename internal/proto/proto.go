package proto

import (
    "bufio"
    "bytes"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "os"
)

type Message struct {
    ID       string `json:"id"`
    Type     string `json:"type"` // register, build_id, file, file_ack, cmd, cmd_result, pull_file, ping, pong, info, info_result
    ClientID string `json:"client_id,omitempty"`

    BuildID string `json:"build_id,omitempty"`

    // file
    FilePath string `json:"file_path,omitempty"`
    Checksum string `json:"checksum,omitempty"`
    Data     []byte `json:"data,omitempty"`

    // cmd
    Command  string `json:"command,omitempty"`
    Output   string `json:"output,omitempty"`
    ExitCode int    `json:"exit_code,omitempty"`

    // info
    Hostname string `json:"hostname,omitempty"`
    OS       string `json:"os,omitempty"`
    Arch     string `json:"arch,omitempty"`
    Username string `json:"username,omitempty"`

    Error string `json:"error,omitempty"`
}

// length-prefixed JSON frames: [uint32 big endian length][payload]
func WriteJSON(w io.Writer, msg *Message) error {
    b, err := json.Marshal(msg)
    if err != nil {
        return err
    }

    var lenbuf [4]byte
    binary.BigEndian.PutUint32(lenbuf[:], uint32(len(b)))
    if _, err := w.Write(lenbuf[:]); err != nil {
        return err
    }

    _, err = w.Write(b)
    return err
}

func ReadJSON(r *bufio.Reader, out *Message) error {
    var lenbuf [4]byte
    if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
        return err
    }

    n := binary.BigEndian.Uint32(lenbuf[:])
    if n == 0 || n > 1<<30 {
        return fmt.Errorf("invalid frame length %d", n)
    }

    buf := make([]byte, n)
    if _, err := io.ReadFull(r, buf); err != nil {
        return err
    }

    return json.Unmarshal(buf, out)
}

func NewID() string {
    var b [16]byte
    _, _ = rand.Read(b[:])
    return hex.EncodeToString(b[:])
}

func SHA256Hex(data []byte) string {
    sum := sha256.Sum256(data)
    return hex.EncodeToString(sum[:])
}

func SHA256FileHex(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
        return "", err
    }

    defer f.Close()
    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return "", err
    }

    return hex.EncodeToString(h.Sum(nil)), nil
}

// small helper to limit in-memory copies for big files when needed later.
func JoinBytes(parts ...[]byte) []byte {
    return bytes.Join(parts, nil)
}

