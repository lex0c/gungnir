package secure

import (
    "crypto/rand"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "sync"
    "sync/atomic"
    
    "golang.org/x/crypto/nacl/box"
)

const (
    opHello      = byte(0)   // client -> server: [opHello][clientPub:32]
    opHelloReply = byte(100) // server -> client: [opHelloReply][serverPub:32]

    nonceSize = 24
    maxFrame  = 8 << 20 // 8 MiB per msg
)

var (
    ErrAuthFail  = errors.New("secure: auth fail")
    ErrFrameSize = errors.New("secure: very large frame")
)

type Session struct {
    c        net.Conn
    isServer bool

    mu     sync.Mutex
    shared [32]byte
    txCtr  uint64
    rxCtr  uint64

    localPub [32]byte
    localSec [32]byte
    peerPub  [32]byte
}

// ========== Handshake ==========

// Client: pinning
func Client(c net.Conn, serverPub [32]byte) (*Session, error) {
    pub, sec, err := box.GenerateKey(rand.Reader)
    if err != nil { return nil, err }
    clPub, clSec := *pub, *sec

    if _, err := c.Write(append([]byte{opHello}, clPub[:]...)); err != nil { return nil, err }

    reply := make([]byte, 1+32)
    if _, err := io.ReadFull(c, reply); err != nil { return nil, err }
    if reply[0] != opHelloReply { return nil, errors.New("secure: invalid handshake") }

    var srvPubReply [32]byte
    copy(srvPubReply[:], reply[1:])
    if srvPubReply != serverPub { return nil, errors.New("secure: server pubkey does not match pin") }

    var shared [32]byte
    box.Precompute(&shared, &serverPub, &clSec)

    return &Session{
        c:        c,
        isServer: false,
        shared:   shared,
        localPub: clPub,
        localSec: clSec,
        peerPub:  serverPub,
    }, nil
}

// ClientTOFU: trust-on-first-use
func ClientTOFU(c net.Conn, getPinned func() ([32]byte, bool), setPinned func([32]byte) error) (*Session, error) {
    pub, sec, err := box.GenerateKey(rand.Reader)
    if err != nil { return nil, err }
    clPub, clSec := *pub, *sec

    if _, err := c.Write(append([]byte{opHello}, clPub[:]...)); err != nil { return nil, err }

    reply := make([]byte, 1+32)
    if _, err := io.ReadFull(c, reply); err != nil { return nil, err }
    if reply[0] != opHelloReply { return nil, errors.New("secure: invalid handshake") }

    var srvPub [32]byte
    copy(srvPub[:], reply[1:])

    if pinned, ok := getPinned(); ok {
        if pinned != srvPub { return nil, errors.New("secure: server pubkey does not match pin") }
    } else {
        if err := setPinned(srvPub); err != nil { return nil, err }
    }

    var shared [32]byte
    box.Precompute(&shared, &srvPub, &clSec)

    return &Session{
        c:        c,
        isServer: false,
        shared:   shared,
        localPub: clPub,
        localSec: clSec,
        peerPub:  srvPub,
    }, nil
}

func Server(c net.Conn, serverPub, serverSec [32]byte) (*Session, error) {
    buf := make([]byte, 1+32)
    if _, err := io.ReadFull(c, buf); err != nil {
        return nil, err
    }

    if buf[0] != opHello {
        return nil, errors.New("secure: invalid hello")
    }

    var clientPub [32]byte
    copy(clientPub[:], buf[1:])

    if _, err := c.Write(append([]byte{opHelloReply}, serverPub[:]...)); err != nil {
        return nil, err
    }

    var shared [32]byte
    box.Precompute(&shared, &clientPub, &serverSec)

    return &Session{
        c:        c,
        isServer: true,
        shared:   shared,
        localPub: serverPub,
        localSec: serverSec,
        peerPub:  clientPub,
    }, nil
}

// ========== Rekey + Repin ==========

// Server applies new static server pair in this session
func (s *Session) RekeyServer(newServerPub, newServerSec [32]byte) {
    s.mu.Lock()
    defer s.mu.Unlock()

    var shared [32]byte
    box.Precompute(&shared, &s.peerPub, &newServerSec)

    s.shared = shared
    s.localPub = newServerPub
    s.localSec = newServerSec
    s.txCtr, s.rxCtr = 0, 0
}

// Client applies new server pub, updates pin via callback
func (s *Session) RekeyClientTOFU(newServerPub [32]byte, setPinned func([32]byte) error) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    var shared [32]byte
    box.Precompute(&shared, &newServerPub, &s.localSec)

    if err := setPinned(newServerPub); err != nil {
        return err
    }

    s.shared = shared
    s.peerPub = newServerPub
    s.txCtr, s.rxCtr = 0, 0
    return nil
}

// ========== Framing AEAD ==========

func (s *Session) WriteMsg(plain []byte) error {
    if len(plain) > maxFrame {
        return ErrFrameSize
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    nonce := make([]byte, nonceSize)
    if s.isServer {
        copy(nonce[:2], []byte("RX"))
    } else {
        copy(nonce[:2], []byte("TX"))
    }

    ctr := atomic.AddUint64(&s.txCtr, 1) - 1
    binary.LittleEndian.PutUint64(nonce[nonceSize-8:], ctr)

    cipher := box.SealAfterPrecomputation(nil, plain, (*[24]byte)(nonce), &s.shared)

    var lenbuf [4]byte
    binary.BigEndian.PutUint32(lenbuf[:], uint32(len(cipher)))
    if _, err := s.c.Write(lenbuf[:]); err != nil {
        return err
    }

    _, err := s.c.Write(cipher)
    return err
}

func (s *Session) ReadMsg() ([]byte, error) {
    var lenbuf [4]byte
    if _, err := io.ReadFull(s.c, lenbuf[:]); err != nil {
        return nil, err
    }

    n := binary.BigEndian.Uint32(lenbuf[:])
    if n > maxFrame {
        return nil, ErrFrameSize
    }

    cipher := make([]byte, n)
    if _, err := io.ReadFull(s.c, cipher); err != nil {
        return nil, err
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    nonce := make([]byte, nonceSize)
    if s.isServer {
        copy(nonce[:2], []byte("TX"))
    } else {
        copy(nonce[:2], []byte("RX"))
    }

    ctr := atomic.AddUint64(&s.rxCtr, 1) - 1
    binary.LittleEndian.PutUint64(nonce[nonceSize-8:], ctr)

    plain, ok := box.OpenAfterPrecomputation(nil, cipher, (*[24]byte)(nonce), &s.shared)
    if !ok {
        return nil, ErrAuthFail
    }

    return plain, nil
}

