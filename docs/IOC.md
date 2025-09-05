# IoCs (Indicators of Compromise)

## Disk Artifacts

* **`~/.ssh/g_server.hex`**
  Created on first execution to pin the server’s public key (TOFU).
* **`~/.gungnir`**
  Local “kill switch”: if present, prevents the client from starting.
* **Go binary “client”**

  * Common name: `client` (may vary depending on the build).

## Processes

* Execution of a Go-compiled binary named `client` (name may vary by build).
* Outbound connections repeatedly initiated by this process.

## Network

* **Default outbound TCP ports**: range **4000–9009**.
* **Periodic reconnection**: attempts to reconnect approximately every 10 minutes.
* **Traffic structure**: fixed framing with

  * 4 bytes → message length.
  * 24 bytes → NaCl nonce.
* **DGA (Domain Generation Algorithm)**: resolution of multiple pseudo-random domains with common TLDs.

## Behavioral Indicators

* Client acts as a **beacon** → establishes connection and waits for instructions.
* Generates **non-TLS traffic**, even on high ports, differing from legitimate HTTPS flows.
* High-entropy domain names when the DGA is active.

## Network Detection

* **IDS/IPS Signatures**

  * Look for outbound connections to TCP ports **4000–9009**.
  * Flag flows where payloads do not match valid TLS handshakes.
  * Detect message framing patterns: **4-byte length field followed by 24-byte nonce**.

* **DNS Monitoring**

  * Identify repeated queries for domains with **high entropy** or pseudo-random strings.
  * Correlate with TLDs commonly used in DGAs (`.com`, `.net`, `.org`).

* **Beaconing Behavior**

  * Hunt for periodic connections from the same host to changing destinations.

* **SIEM Correlation**

  * Rule: if a host initiates **outbound connections in the 4000–9009 range** *and* queries multiple pseudo-random domains, trigger an alert.
