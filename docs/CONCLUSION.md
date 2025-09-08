# Conclusion

> Beaconing Strategy: don’t reinvent, blend in

Using periodic HTTPS requests as beacons is generally a far more effective strategy than maintaining a raw, persistent socket. HTTPS blends seamlessly into ordinary web traffic, passes through firewalls and proxies without raising suspicion, and leverages strong encryption to obscure payloads. A beaconing pattern with randomized intervals and plausible request headers makes detection significantly harder, while still allowing the server to push tasks and receive results efficiently. In contrast, long-lived custom sockets stand out in telemetry and are easily fingerprinted.
