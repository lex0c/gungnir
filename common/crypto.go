package common

import (
    "bufio"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "math/big"
    "net"
    "fmt"
    "io"
    "os"
    "time"
    
    "golang.org/x/crypto/nacl/box"
)

const (
    // Plain opcodes
    OpHello      = byte(0)   // client -> server: [OpHello][clientPub:32]
    OpHelloReply = byte(100) // server -> client: [OpHelloReply][serverPub:32]
    OpReset      = byte(9)   // client -> server: [OpReset][clientPub:32]

    // Encrypted opcodes
    UploadFile = byte(1)
    CmdExecRaw = byte(2)

    EncFlagEncrypted = byte(1)

    NonceSize      = 24
    PubKeySize     = 32
    MaxFrameCipher = 64 << 20 // 64 MiB

    ReadDeadline  = 180 * time.Second
    WriteDeadline = 60 * time.Second
)

type KeyPair struct {
    Public  [PubKeySize]byte
    Private [PubKeySize]byte
}

func LoadOrCreateKeypair(privPath, pubPath string) (*KeyPair, error) {
    k := &KeyPair{}

    priv, err1 := os.ReadFile(privPath)
    pub, err2 := os.ReadFile(pubPath)

    if err1 == nil && err2 == nil && len(priv) == PubKeySize && len(pub) == PubKeySize {
        copy(k.Private[:], priv)
        copy(k.Public[:], pub)
        return k, nil
    }

    pubN, privN, err := box.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }

    k.Public = *pubN
    k.Private = *privN

    if err := os.WriteFile(privPath, k.Private[:], 0o600); err != nil {
        return nil, err
    }

    if err := os.WriteFile(pubPath, k.Public[:], 0o644); err != nil {
        return nil, err
    }

    return k, nil
}

func LoadPubKey(path string) (*[PubKeySize]byte, error) {
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    if len(b) != PubKeySize {
        return nil, fmt.Errorf("pubkey size invalid")
    }

    var pk [PubKeySize]byte
    copy(pk[:], b)

    return &pk, nil
}

func SavePubKey(path string, pub *[PubKeySize]byte) error {
    return os.WriteFile(path, pub[:], 0o644)
}

func BoxEncrypt(toPub *[PubKeySize]byte, plaintext []byte) (ephPub [PubKeySize]byte, nonce [NonceSize]byte, ciphertext []byte, err error) {
    ephPubPtr, ephPriv, err := box.GenerateKey(rand.Reader)
    if err != nil {
        return
    }

    ephPub = *ephPubPtr
    if _, err = rand.Read(nonce[:]); err != nil {
        return
    }

    ciphertext = box.Seal(nil, plaintext, &nonce, toPub, ephPriv)

    return
}

func BoxDecrypt(myPriv *[PubKeySize]byte, fromEphPub *[PubKeySize]byte, nonce *[NonceSize]byte, ciphertext []byte) ([]byte, error) {
    pt, ok := box.Open(nil, ciphertext, nonce, fromEphPub, myPriv)
    if !ok {
        return nil, fmt.Errorf("decryption failed")
    }

    return pt, nil
}

// [opcode:1][enc:1=1][senderStaticPub:32][senderEphPub:32][nonce:24][cipherLen:u32][ciphertext]

func WriteEncryptedFrame(w io.Writer, opcode byte, senderStaticPub *[PubKeySize]byte, toPub *[PubKeySize]byte, plaintext []byte) error {
    if len(plaintext) > MaxFrameCipher {
        return fmt.Errorf("payload too large")
    }

    ephPub, nonce, cipher, err := BoxEncrypt(toPub, plaintext)
    if err != nil {
        return err
    }

    bw := bufio.NewWriter(w)

    // opcode + enc flag
    if _, err := bw.Write([]byte{opcode, EncFlagEncrypted}); err != nil {
        return err
    }

    // sender static pub
    if _, err := bw.Write(senderStaticPub[:]); err != nil {
        return err
    }

    // sender ephemeral pub
    if _, err := bw.Write(ephPub[:]); err != nil {
        return err
    }

    // nonce
    if _, err := bw.Write(nonce[:]); err != nil {
        return err
    }

    // cipher len + body
    if err := binary.Write(bw, binary.LittleEndian, uint32(len(cipher))); err != nil {
        return err
    }

    if _, err := bw.Write(cipher); err != nil {
        return err
    }

    return bw.Flush()
}

func ReadEncryptedFrame(r io.Reader) (opcode byte, senderStatic [PubKeySize]byte, senderEph [PubKeySize]byte, nonce [NonceSize]byte, cipher []byte, err error) {
    var hdr [2]byte
    if _, err = io.ReadFull(r, hdr[:]); err != nil {
        return
    }

    opcode = hdr[0]
    if hdr[1] != EncFlagEncrypted {
        err = fmt.Errorf("enc flag not 1")
        return
    }

    if _, err = io.ReadFull(r, senderStatic[:]); err != nil {
        return
    }

    if _, err = io.ReadFull(r, senderEph[:]); err != nil {
        return
    }

    if _, err = io.ReadFull(r, nonce[:]); err != nil {
        return
    }

    var clen uint32
    if err = binary.Read(r, binary.LittleEndian, &clen); err != nil {
        return
    }

    if clen > MaxFrameCipher {
        err = fmt.Errorf("cipher too large")
        return
    }

    cipher = make([]byte, clen)
    _, err = io.ReadFull(r, cipher)

    return
}

func MarshalExecPayload(cmd string, timeoutSec uint32) []byte {
    cb := []byte(cmd)
    buf := make([]byte, 4+len(cb)+4)
    off := 0
    binary.LittleEndian.PutUint32(buf[off:], uint32(len(cb)))
    off += 4
    copy(buf[off:], cb)
    off += len(cb)
    binary.LittleEndian.PutUint32(buf[off:], timeoutSec)
    return buf
}

func UnmarshalExecPayload(plain []byte) (cmd string, timeoutSec uint32, err error) {
    if len(plain) < 8 {
        return "", 0, fmt.Errorf("short exec payload")
    }

    cmdLen := binary.LittleEndian.Uint32(plain[:4])
    if int(4+cmdLen+4) != len(plain) {
        return "", 0, fmt.Errorf("malformed exec payload")
    }

    cmd = string(plain[4 : 4+cmdLen])
    timeoutSec = binary.LittleEndian.Uint32(plain[4+cmdLen : 8+cmdLen])

    return
}

func MarshalUploadPayload(path string, data []byte) []byte {
    sum := sha256.Sum256(data)
    pb := []byte(path)
    buf := make([]byte, 4+len(pb)+8+len(data)+32)
    off := 0
    binary.LittleEndian.PutUint32(buf[off:], uint32(len(pb)))
    off += 4
    copy(buf[off:], pb)
    off += len(pb)
    binary.LittleEndian.PutUint64(buf[off:], uint64(len(data)))
    off += 8
    copy(buf[off:], data)
    off += len(data)
    copy(buf[off:], sum[:])
    return buf
}

func UnmarshalUploadPayload(plain []byte, maxPath uint32, maxSize uint64) (path string, body []byte, err error) {
    if len(plain) < 4 {
        return "", nil, fmt.Errorf("short upload payload")
    }

    pLen := binary.LittleEndian.Uint32(plain[:4])
    if pLen == 0 || pLen > maxPath {
        return "", nil, fmt.Errorf("invalid pathLen")
    }

    // 4 bytes do pathLen + pLen bytes do path + 8 bytes do size
    if len(plain) < int(4+uint32(pLen)+8) {
        return "", nil, fmt.Errorf("short after path")
    }

    path = string(plain[4 : 4+int(pLen)])
    off := 4 + int(pLen)

    size := binary.LittleEndian.Uint64(plain[off : off+8])
    off += 8

    if size == 0 || size > maxSize {
        return "", nil, fmt.Errorf("invalid fileSize")
    }

    // tamanho total esperado: header + body + sha256
    expectedTotal := off + int(size) + 32
    if len(plain) != expectedTotal {
        return "", nil, fmt.Errorf("malformed payload size")
    }

    body = make([]byte, int(size))
    copy(body, plain[off:off+int(size)])
    off += int(size)

    want := plain[off : off+32]
    sum := sha256.Sum256(body)
    if !constEq(sum[:], want) {
        return "", nil, fmt.Errorf("BAD_HASH")
    }

    return
}

// HELLO:       [OpHello][clientPub:32]
// HELLO_REPLY: [OpHelloReply][serverPub:32]
// RESET:       [OpReset][clientPub:32]

func WriteHello(w io.Writer, clientPub *[PubKeySize]byte) error {
    bw := bufio.NewWriter(w)
    if _, err := bw.Write([]byte{OpHello}); err != nil {
        return err
    }

    if _, err := bw.Write(clientPub[:]); err != nil {
        return err
    }

    return bw.Flush()
}

func ReadHello(r io.Reader) (*[PubKeySize]byte, error) {
    var cpub [PubKeySize]byte
    if _, err := io.ReadFull(r, cpub[:]); err != nil {
        return nil, err
    }

    return &cpub, nil
}

func WriteHelloReply(w io.Writer, serverPub *[PubKeySize]byte) error {
    bw := bufio.NewWriter(w)
    if _, err := bw.Write([]byte{OpHelloReply}); err != nil {
        return err
    }

    if _, err := bw.Write(serverPub[:]); err != nil {
        return err
    }

    return bw.Flush()
}

func ReadHelloReply(r io.Reader) (*[PubKeySize]byte, error) {
    var op [1]byte
    if _, err := io.ReadFull(r, op[:]); err != nil {
        return nil, err
    }

    if op[0] != OpHelloReply {
        return nil, fmt.Errorf("unexpected opcode %d", op[0])
    }

    var spub [PubKeySize]byte
    if _, err := io.ReadFull(r, spub[:]); err != nil {
        return nil, err
    }

    return &spub, nil
}

func WriteReset(w io.Writer, clientPub *[PubKeySize]byte) error {
    bw := bufio.NewWriter(w)
    if _, err := bw.Write([]byte{OpReset}); err != nil {
        return err
    }

    if _, err := bw.Write(clientPub[:]); err != nil {
        return err
    }

    return bw.Flush()
}

func GetFreePortInRange(host string, min, max int) (int, net.Listener, error) {
    if min <= 0 || max <= 0 || min > max {
        return 0, nil, fmt.Errorf("invalid range: min=%d max=%d", min, max)
    }

    ports := make([]int, 0, max-min+1)
    for p := min; p <= max; p++ {
        ports = append(ports, p)
    }

    if err := shuffleCrypto(ports); err != nil {
        return 0, nil, fmt.Errorf("shuffle fail: %w", err)
    }

    for _, p := range ports {
        addr := fmt.Sprintf("%s:%d", host, p)
        ln, err := net.Listen("tcp", addr)
        if err == nil {
            return p, ln, nil
        }
    }

    return 0, nil, fmt.Errorf("no free ports in [%d, %d]", min, max)
}

func shuffleCrypto(a []int) error {
    for i := len(a) - 1; i > 0; i-- {
      j, err := cryptoRandInt(i + 1)
      if err != nil {
          return err
      }

      a[i], a[j] = a[j], a[i]
    }

    return nil
}

func cryptoRandInt(n int) (int, error) {
    if n <= 0 {
        return 0, fmt.Errorf("n must be > 0")
    }

    bn, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
    if err != nil {
        return 0, err
    }

    return int(bn.Int64()), nil
}

func constEq(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }

    var v byte
    for i := range a {
        v |= a[i] ^ b[i]
    }

    return v == 0
}

