# Gungnir

Gungnir is a minimal remote command and control system written in Go. A central
server accepts TCP connections from clients over an authenticated and encrypted
channel and exposes a JSON HTTP API for operators. Clients authenticate using a
trust-on-first-use (TOFU) handshake and exchange JSON messages.

## Features

- **JSON protocol** – Messages are framed as length-prefixed JSON structures for
  commands, file transfer and pings
- **NaCl `box` encryption** – Clients and server establish a shared key during a
  TOFU handshake and encrypt all traffic with NaCl's `box` primitive
- **HTTP control API** – The server exposes endpoints to list clients, send
  commands, transfer files and rotate keys

## Handshake

### 1. Initial handshake

1. **Server starts** with an in-memory X25519 key pair (`serverPub`, `serverSec`).
2. **Client generates** an ephemeral pair (`clientPub`, `clientSec`).
3. **Hello →** Client sends `[OpHello][clientPub]`.
4. **HelloReply ←** Server replies with `[OpHelloReply][serverPub]`.
5. **TOFU (Trust On First Use)**
   - If the client already saved a pin for `serverPub`, compare:
     - match → continue.
     - mismatch → fail (possible MitM).
   - If no pin exists, save `serverPub` to `~/.ssh/g_server.hex` with mode `600`.
6. **Shared secret**
   - Both sides run `box.Precompute` with the received public key and their secret key.
   - The result (`shared`) is used with AEAD (`box.SealAfterPrecomputation`).
7. **Session established**
   - From this point, all traffic is encrypted frame by frame (`WriteMsg`/`ReadMsg`).

### 2. Framing and AEAD

Each message is packaged as:

* 4-byte prefix (uint32 big-endian) holding the size of the encrypted payload.
* 24-byte nonce that encodes direction (TX/RX) and a monotonic counter.
* Payload sealed with `box.SealAfterPrecomputation`.

This provides:

* Confidentiality.
* Integrity (MAC).
* Replay rejection via the monotonic counter.

### 3. Rekey with OpReset

When the server decides to rotate keys:

1. **Server generates** a new pair: `newPub`, `newSec`.
2. **Server broadcasts** to all clients:
   ```json
   { "Type": "secure_reset", "ID": "<fingerprint>", "Data": <newPub (32 bytes)> }
   ```
3. **Client on receipt**:
   - Recomputes the shared secret with `newPub`.
   - Updates the pin stored in `~/.ssh/g_server.hex`.
   - Responds with ACK:
     ```json
     { "Type": "secure_reset_ack", "ID": "<fingerprint>" }
     ```
4. **Server on ACK**:
   - Applies `RekeyServer` for that session, switching `shared` to `newSec`.
   - Clears `pendingPub`/`pendingSec`.
5. **Result**: traffic resumes encrypted with the new keys and the client pin is updated.

## Security implications

* An attacker intercepting the **first connection** can supply a fake key and maintain a MitM indefinitely.
* The pin file (`~/.ssh/g_server.hex`) is a target; if compromised or corrupted, the client may accept malicious keys or fail to connect.
* Lack of forward secrecy between resets means that if the shared key is exposed, previously captured traffic can be decrypted.
* Nonce reuse or counter failures can break the confidentiality provided by AEAD.

## Building

```sh
make
```

Individual components can be built separately:

```sh
make server   # builds bin/server
make client   # builds bin/client
```

## Running

### Server

The server listens on a TCP socket for client sessions and serves an HTTP API.
Addresses can be configured via environment variables:

- `SOCK_ADDR` (default `:9000`) – TCP listener for secure sessions
- `HTTP_ADDR` (default `:8080`) – HTTP API address

Example:

```sh
SOCK_ADDR=":9000" HTTP_ADDR=":8080" ./bin/server
```

### Client

Clients connect to the server, perform the TOFU handshake and register with a
combined identifier. Optionally supply a custom id:

```sh
./bin/client -id my-client
```


## HTTP API examples

Interact with the server's HTTP API using `curl`.

List connected clients:

```sh
curl http://localhost:8080/clients
```

Send a command to a specific client:

```sh
curl -X POST http://localhost:8080/send-cmd \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>","command":"whoami"}'
```

Broadcast a command to all clients:

```sh
curl -X POST http://localhost:8080/send-cmd \
  -H 'Content-Type: application/json' \
  -d '{"command":"uptime"}'
```

Push a file to a client:

```sh
curl -X POST http://localhost:8080/send-file \
  -F client_id=<id> \
  -F path=/tmp/hello.txt \
  -F file=@hello.txt
```

Pull a file from a client:

```sh
curl -X POST http://localhost:8080/pull-file \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>","src_path":"/etc/hosts","dst_path":"hosts-copy"}'
```

Rotate keys for all clients:

```sh
curl -X POST http://localhost:8080/rotate-keys
```


## Testing

Run the full test suite with:

```sh
go test ./...
```

## License

This project is licensed under the terms of the MIT License. See [LICENSE](LICENSE).

