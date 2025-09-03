#!/usr/bin/env python

import argparse, base64, io, json, math, os, re, sys
from collections import Counter


PRINTABLE_ASCII = set(range(0x20, 0x7f))  # space..~ (without \n,\r,\t)
TAB = 0x09  # some strings
DEFAULT_MIN_LEN = 4

PATTERNS = {
    "url": re.compile(r"https?://[^\s'\"<>]{4,}", re.I),
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "linux_path": re.compile(r"/(?:bin|sbin|usr|etc|var|tmp|home|proc|dev)(?:/[A-Za-z0-9._@%+~#=-]+){1,}"),
    "rev_shell_cmd": re.compile(
        r"\b(?:nc|ncat|netcat|socat|openssl|curl|wget|bash|sh|python|perl|php|ruby)\b.*", re.I
    ),
    "ssh_tunnel": re.compile(r"\bssh\b.*\s-[LR]\s", re.I),
    "persistence": re.compile(r"(?:systemd|\.service|rc\.local|/etc/init\.d|update-rc\.d|crontab|/etc/cron\.)", re.I),
    "crypto_key": re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) (?:PRIVATE|PUBLIC) KEY-----"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "jwt_like": re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b"),
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0

    cnt = Counter(s)
    n = len(s)

    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def looks_base64(s: str) -> bool:
    if len(s) < 32 or len(s) % 4 != 0:
        return False

    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return False

    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def extract_ascii_strings(buf: bytes, min_len=DEFAULT_MIN_LEN):
    out = []
    i = 0
    n = len(buf)

    while i < n:
        b = buf[i]
        if b in PRINTABLE_ASCII or b == TAB:
            start = i
            i += 1

            while i < n and (buf[i] in PRINTABLE_ASCII or buf[i] == TAB):
                i += 1

            if i - start >= min_len:
                try:
                    s = buf[start:i].decode("ascii", "ignore")
                except Exception:
                    s = None
                if s:
                    out.append((start, s, "ascii"))
        else:
            i += 1

    return out


def extract_utf16le_strings(buf: bytes, min_len=DEFAULT_MIN_LEN):
    # (printable \x00){min_len+}
    pat = re.compile((r"(?:[\x20-\x7e]\x00){%d,}" % min_len).encode())
    out = []

    for m in pat.finditer(buf):
        start = m.start()
        try:
            s = m.group().decode("utf-16le", "ignore")
        except Exception:
            continue
        out.append((start, s, "utf16le"))

    return out


def classify(s: str):
    tags = []

    for name, rx in PATTERNS.items():
        if rx.search(s):
            tags.append(name)

    b64 = looks_base64(s)
    ent = shannon_entropy(s)

    if ent >= 4.5:
        tags.append("high_entropy")
    if b64:
        tags.append("base64")

    return tags, ent, b64


def scan_file(path: str, min_len=DEFAULT_MIN_LEN, include_utf16=True, only_tags=None, max_hits=None):
    with open(path, "rb") as f:
        buf = f.read()

    hits = []
    for offset, s, kind in extract_ascii_strings(buf, min_len):
        tags, ent, b64 = classify(s)
        if only_tags and not (set(tags) & set(only_tags)):
            continue

        if tags:
            hits.append({"off": offset, "kind": kind, "len": len(s), "tags": tags, "entropy": round(ent, 3), "str": s})
            if max_hits and len(hits) >= max_hits:
                return hits

    if include_utf16:
        for offset, s, kind in extract_utf16le_strings(buf, min_len):
            tags, ent, b64 = classify(s)
            if only_tags and not (set(tags) & set(only_tags)):
                continue

            if tags:
                hits.append({"off": offset, "kind": kind, "len": len(s), "tags": tags, "entropy": round(ent, 3), "str": s})
                if max_hits and len(hits) >= max_hits:
                    return hits

    hits.sort(key=lambda h: (len(h["tags"]), h["entropy"], h["len"]), reverse=True)

    return hits


def main():
    ap = argparse.ArgumentParser(description="Scan de strings (ASCII + UTF-16LE).")
    ap.add_argument("file", help="Bin path")
    ap.add_argument("--min-len", type=int, default=DEFAULT_MIN_LEN, help="String length (default: 4)")
    ap.add_argument("--no-utf16", action="store_true", help="Disable find strings UTF-16LE")
    ap.add_argument("--only", nargs="+", help="Tag filter (ex: url domain rev_shell_cmd)")
    ap.add_argument("--max-hits", type=int, help="Max hits")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    hits = scan_file(
        args.file,
        min_len=args.min_len,
        include_utf16=not args.no_utf16,
        only_tags=args.only,
        max_hits=args.max_hits,
    )

    if args.json:
        print(json.dumps({"file": args.file, "hits": hits}, ensure_ascii=False, indent=2))
        return

    if not hits:
        print("Sothing useful found.")
        return

    print(f"# Suspect strings in {args.file}  (hits={len(hits)})")
    for h in hits:
        off = f"0x{h['off']:08x}"
        tags = ",".join(h["tags"])

        print(f"[{off}] ({h['kind']}, len={h['len']}, H={h['entropy']}) [{tags}]")

        s = h["str"]
        if len(s) > 240:
            s = s[:240] + "…"

        print(f"  {s}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass

