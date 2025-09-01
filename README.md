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

## Testing

Run the full test suite with:

```sh
go test ./...
```

## License

This project is licensed under the terms of the MIT License. See [LICENSE](LICENSE).

