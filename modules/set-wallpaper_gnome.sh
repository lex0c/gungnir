#!/usr/bin/env bash
# Use: sudo ./set-wallpaper.sh /path/to/img.jpg

set -euo pipefail

IMG="${1:-}"
if [[ -z "$IMG" ]]; then
  echo "use: $0 /path/to/img.jpg" >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "required root" >&2
  exit 1
fi
if [[ ! -f "$IMG" ]]; then
  echo "file not found: $IMG" >&2
  exit 1
fi

URI="file://$(readlink -f "$IMG")"

apply_gsettings_live() {
  local user="$1" uid="$2"
  local runtime="/run/user/$uid"
  local bus="${runtime}/bus"

  if [[ -S "$bus" ]]; then
    sudo -u "$user" \
      XDG_RUNTIME_DIR="$runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" \
      HOME="$(getent passwd "$user" | cut -d: -f6)" \
      gsettings set org.gnome.desktop.background picture-uri "$URI" || return 1

    sudo -u "$user" \
      XDG_RUNTIME_DIR="$runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" \
      HOME="$(getent passwd "$user" | cut -d: -f6)" \
      gsettings set org.gnome.desktop.background picture-uri-dark "$URI" || return 1

    sudo -u "$user" \
      XDG_RUNTIME_DIR="$runtime" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" \
      HOME="$(getent passwd "$user" | cut -d: -f6)" \
      gsettings set org.gnome.desktop.interface color-scheme "prefer-dark" || return 1

    return 0
  fi
  return 1
}

install_autostart() {
  local user="$1" home_dir="$2"
  local autostart_dir="$home_dir/.config/autostart"
  local desktop="$autostart_dir/set-wallpaper-on-login.desktop"

  mkdir -p "$autostart_dir"
  cat > "$desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Set Wallpaper
Exec=/bin/sh -c 'gsettings set org.gnome.desktop.background picture-uri "$URI" && gsettings set org.gnome.desktop.background picture-uri-dark "$URI" && gsettings set org.gnome.desktop.interface color-scheme "prefer-dark"'
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF
  chown -R "$user":"$user" "$autostart_dir"
}

while IFS=: read -r user _ uid _ _ home _; do
  [[ "$uid" -ge 1000 && -d "$home" ]] || continue

  echo "[*] user: $user (uid=$uid)"
  if apply_gsettings_live "$user" "$uid"; then
    install_autostart "$user" "$home"
    echo "    ok"
  else
    echo "    without DBus session; create autostart"
    install_autostart "$user" "$home"
  fi
done < <(getent passwd)

echo "[✓] done: $URI"

