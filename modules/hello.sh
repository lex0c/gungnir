#!/usr/bin/env bash
# Uso: sudo ./hello.sh /tmp/hello.txt 10

set -euo pipefail

SRC="${1:-}"
N="${2:-}"

if [[ -z "${SRC}" || -z "${N}" ]]; then
  echo "use: $0 <origem> <qtd>" >&2
  exit 1
fi
if [[ ! -f "$SRC" ]]; then
  echo "file not found: $SRC" >&2
  exit 1
fi

find_desktop_dir() {
  local home="$1"
  local cfg="$home/.config/user-dirs.dirs"

  if command -v xdg-user-dir >/dev/null 2>&1; then
    dir=$(HOME="$home" xdg-user-dir DESKTOP 2>/dev/null || true)
    if [[ -n "$dir" && -d "$dir" ]]; then
      echo "$dir"; return
    fi
  fi

  if [[ -f "$cfg" ]]; then
    # shellcheck disable=SC1090
    source "$cfg"
    if [[ -n "${XDG_DESKTOP_DIR:-}" ]]; then
      eval "dir=${XDG_DESKTOP_DIR}"
      [[ -d "$dir" ]] && { echo "$dir"; return; }
    fi
  fi

  for cand in "$home/Desktop" "$home/Área de Trabalho"; do
    [[ -d "$cand" ]] && { echo "$cand"; return; }
  done

  mkdir -p "$home/Desktop"
  echo "$home/Desktop"
}

base="$(basename -- "$SRC")"
name="${base%.*}"
ext=""
[[ "$base" == *.* ]] && ext=".${base##*.}"

for home in /home/*; do
  user=$(basename "$home")
  [[ -d "$home" ]] || continue

  echo "[*] User: $user"
  desk=$(find_desktop_dir "$home")

  for i in $(seq 1 "$N"); do
    dest="${desk}/${name}-${i}${ext}"
    cp -- "$SRC" "$dest"
    chown "$user:$user" "$dest"
    echo "    -> $dest"
  done
done

echo "[✓] done"

