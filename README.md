# RCE POC

Minimal experimental **end-to-end encrypted client/server** written in Go.

## Features

* Keypair generation and storage for the client (`client_pub.bin` / `client_priv.bin`).
* Server keypair generated in memory at startup.
* Simple handshake (`HELLO`, `HELLO_REPLY`, `RESET`).
* Encrypted operations:

  * **Exec**: run an arbitrary shell command remotely and return stdout/stderr.
  * **UploadFile**: send a file (binary, txt) with SHA-256 integrity check.

## Build

```bash
make build
```

## Run

Start the server:

```bash
make run-server
```

Sync the client with the server to obtain its public key:

```bash
./bin/client -sync
```

Execute a remote command:

```bash
./bin/client -mode exec -cmd "uname -a"
```

Upload a file:

```bash
./bin/client -mode upload -file ./foobar.txt -path /tmp/foobar.txt
```

## Security implications

The project is educational and intentionally minimal. Serious flaws remain:

* **Trust on first use**: The client trusts the first `server_pub` it sees. A MITM attacker can hijack the initial sync.
* **No replay protection**: Messages can be re-sent and re-executed by the server.
* **Traffic analysis**: Frame sizes and timing still leak metadata. There is no padding or cover traffic.
* **No authentication / ACL**: Any client holding a pub/priv keypair can interact with the server.

