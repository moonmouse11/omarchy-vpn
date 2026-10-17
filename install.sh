#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Backend lives outside the plugin dir: omarchy-shell hot-reloads plugins on
# any write under ~/.config/omarchy/plugins (python's __pycache__ included).
INSTALL_DIR="$HOME/.local/share/omarchy-vpn"
PLUGIN_ID="omarchy-vpn"
PLUGIN_DIR="$HOME/.config/omarchy/plugins/$PLUGIN_ID"
LEGACY_DIR="$HOME/.config/waybar/vpn-manager"   # Omarchy 3 / waybar install

if ! command -v omarchy-shell >/dev/null; then
    echo "error: omarchy-shell not found — this version needs Omarchy 4" >&2
    echo "       (the Omarchy 3 / waybar version lives in its own repository)" >&2
    exit 1
fi

echo "==> omarchy-vpn installer"
echo ""

# ── Dependencies ──────────────────────────────────────────────────────────────

echo "==> Installing dependencies..."
sudo pacman -S --needed --noconfirm python wireguard-tools openvpn openresolv socat

# ── sudoers rule ──────────────────────────────────────────────────────────────

SUDOERS_FILE="/etc/sudoers.d/vpn-manager"
# Managed by this installer: rewrite on every run so upgrades pick up new rules.
# Rules are narrowed to the exact call patterns used by the providers:
#   wg-quick/awg-quick up/down <profile>, openvpn --config/--daemon/--writepid
#   (+ --script-security/--up/--down wiring openvpn-dns-updown, see below),
#   mkdir/rm/cp/chmod only under /run/openvpn, /etc/wireguard,
#   /etc/amnezia/amneziawg, /etc/openvpn/client,
#   cat on the same config globs (menu-imported configs are root:0600 — the
#   background ping sweep reads endpoints via 'sudo -n cat'),
#   systemctl enable/disable wg-quick@* / awg-quick@*, happ-killswitch (root-owned script),
#   sysctl -w net.ipv6.conf.{all,default}.disable_ipv6={0,1} (IPv6 leak guard —
#   none of the providers tunnel IPv6, so it's turned off system-wide while any
#   tunnel is up and restored on full disconnect, see src/ipv6guard.py).
# openvpn-dns-updown (root-owned, see scripts/) applies OpenVPN-pushed DNS via
# systemd-resolved on connect and reverts it on disconnect — without it,
# server-pushed DNS is silently ignored on Linux, same class of leak as the
# xray dns-out fix in happmeta.py. It needs no sudoers entry of its own:
# openvpn already runs as root here, so its --up/--down child does too.
# `kill <pid>` stays broad (arbitrary numeric PIDs cannot be pattern-matched).
# THREAT MODEL: sudoers matches command arguments lexically and `*` spans
# `/` and `..`, so `sudo -n cat /etc/wireguard/../../../etc/shadow` matches
# the cat rules below — i.e. the cat entries are equivalent to root read
# access, and together with the unbounded `cp *` source they allow reading
# back any root file the user could copy there. Accepted deliberately: this
# installer targets a single-user machine whose owner already runs it with
# full interactive sudo (pacman, tee into /etc/sudoers.d, ...), so the owner
# is root-equivalent anyway; the rules only remove a password prompt. Remove
# the two cat entries if that trade-off is unacceptable.
# If a narrowed rule ever blocks a legit call, fall back to the broad form:
#   ... NOPASSWD: /usr/bin/wg-quick, /usr/bin/openvpn, /usr/bin/kill, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/cp, /usr/bin/chmod, ...
echo "==> Writing sudoers rule..."
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg-quick, /usr/bin/awg-quick, /usr/bin/openvpn --config * --daemon --writepid /run/openvpn/client-*.pid --script-security 2 --up /usr/local/bin/openvpn-dns-updown up --down /usr/local/bin/openvpn-dns-updown down --persist-remote-ip, /usr/bin/kill, /usr/bin/mkdir -p /run/openvpn, /usr/bin/rm -f /run/openvpn/client-*.pid, /usr/bin/rm -f /etc/wireguard/*.conf, /usr/bin/rm -f /etc/amnezia/amneziawg/*.conf, /usr/bin/cp * /etc/wireguard/*, /usr/bin/cp * /etc/amnezia/amneziawg/*, /usr/bin/cp * /etc/openvpn/client/*, /usr/bin/chmod 600 /etc/wireguard/*, /usr/bin/chmod 600 /etc/amnezia/amneziawg/*, /usr/bin/chmod 600 /etc/openvpn/client/*, /usr/bin/cat /etc/wireguard/*, /usr/bin/cat /etc/amnezia/amneziawg/*, /usr/bin/cat /etc/openvpn/client/*, /usr/bin/systemctl enable wg-quick@*, /usr/bin/systemctl disable wg-quick@*, /usr/bin/systemctl enable awg-quick@*, /usr/bin/systemctl disable awg-quick@*, /usr/local/bin/happ-killswitch, /usr/bin/sysctl -w net.ipv6.conf.all.disable_ipv6=1, /usr/bin/sysctl -w net.ipv6.conf.all.disable_ipv6=0, /usr/bin/sysctl -w net.ipv6.conf.default.disable_ipv6=1, /usr/bin/sysctl -w net.ipv6.conf.default.disable_ipv6=0" \
    | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE" > /dev/null && echo "==> sudoers rule validated"

# ── killswitch script (root-owned, driven via the NOPASSWD sudoers rule) ─────

echo "==> Installing happ-killswitch to /usr/local/bin..."
sudo cp "$REPO_DIR/scripts/happ-killswitch" /usr/local/bin/happ-killswitch
sudo chown root:root /usr/local/bin/happ-killswitch
sudo chmod 755 /usr/local/bin/happ-killswitch
# Remove the user-writable copy if it exists (superseded by the root-owned one)
rm -f "$HOME/.local/bin/happ-killswitch"

echo "==> Installing openvpn-dns-updown to /usr/local/bin..."
sudo cp "$REPO_DIR/scripts/openvpn-dns-updown" /usr/local/bin/openvpn-dns-updown
sudo chown root:root /usr/local/bin/openvpn-dns-updown
sudo chmod 755 /usr/local/bin/openvpn-dns-updown

# ── /etc/wireguard permissions ────────────────────────────────────────────────

echo "==> Setting /etc/wireguard directory permissions..."
sudo mkdir -p /etc/wireguard
sudo chmod o+rx /etc/wireguard

# ── /etc/amnezia/amneziawg permissions (AmneziaWG, optional) ─────────────────
# Only wires up permissions; amneziawg-tools/amneziawg-dkms are not pulled in
# here (dkms needs matching linux-headers per kernel) — install them yourself
# if you use AmneziaWG, the provider is a no-op without awg-quick.

echo "==> Setting /etc/amnezia/amneziawg directory permissions..."
sudo mkdir -p /etc/amnezia/amneziawg
sudo chmod o+rx /etc/amnezia/amneziawg

# ── /etc/openvpn/client directory ─────────────────────────────────────────────

echo "==> Creating /etc/openvpn/client directory..."
sudo mkdir -p /etc/openvpn/client
sudo chmod 755 /etc/openvpn/client

# ── Fix resolvconf ────────────────────────────────────────────────────────────

if [[ -L /etc/resolv.conf ]]; then
    echo "==> Fixing /etc/resolv.conf for openresolv..."
    sudo rm /etc/resolv.conf
    sudo resolvconf -u
fi

# ── Backend ───────────────────────────────────────────────────────────────────

echo "==> Installing backend to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/src"
cp -r "$REPO_DIR/src" "$INSTALL_DIR/"

# ── omarchy-shell bar widget ──────────────────────────────────────────────────

echo "==> Installing bar widget to $PLUGIN_DIR..."
mkdir -p "$PLUGIN_DIR"
cp "$REPO_DIR/plugin/manifest.json" "$REPO_DIR"/plugin/*.qml "$PLUGIN_DIR/"
omarchy-shell -q shell rescanPlugins
if ! omarchy plugin list | grep -qE "^$PLUGIN_ID[[:space:]]+enabled"; then
    omarchy plugin enable "$PLUGIN_ID" --before omarchy.network \
        || omarchy plugin enable "$PLUGIN_ID" --section right \
        || echo "    could not enable it — run: omarchy plugin enable $PLUGIN_ID"
fi
# the hot reload keeps an already-built widget on its old code (new IPC methods missing)
if omarchy-shell shell ping >/dev/null 2>&1; then
    omarchy restart shell >/dev/null || echo "    restart the shell to load the new widget: omarchy restart shell"
fi

# ── Keybinding (Hyprland Lua config) ──────────────────────────────────────────

# Rewritten on every install: an older block opened the omarchy.menu menu.
BINDINGS="$HOME/.config/hypr/bindings.lua"
if [[ -f "$BINDINGS" ]]; then
    echo "==> SUPER+Shift+V opens the VPN window ($BINDINGS)"
    sed -i '/^-- >>> omarchy-vpn$/,/^-- <<< omarchy-vpn$/d' "$BINDINGS"
    cat >> "$BINDINGS" <<EOF
-- >>> omarchy-vpn
o.bind("SUPER + SHIFT + V", "VPN window", "omarchy-shell -q $PLUGIN_ID window")
o.window({ class = "^org.quickshell$", title = "^VPN$" }, { tag = "+floating-window" })
-- <<< omarchy-vpn
EOF
else
    echo "==> bindings.lua missing, skipping the SUPER+Shift+V binding."
fi

# ── Legacy waybar install ─────────────────────────────────────────────────────
# A running Happ/Keys keeper was started from the old copy: leave it until
# nothing runs from there (reconnect once, then re-run make install).

if [[ -d "$LEGACY_DIR" ]]; then
    if pgrep -f "$LEGACY_DIR/src/" >/dev/null; then
        echo "==> $LEGACY_DIR is still in use by a running connection — kept."
        echo "    Reconnect from the new menu, then run 'make install' again to remove it."
    else
        echo "==> Removing the old waybar install ($LEGACY_DIR)..."
        rm -rf "$LEGACY_DIR"
        rm -f "$HOME/.config/waybar/scripts/vpn-status.sh" "$HOME/.config/waybar/scripts/vpn-menu.sh"
    fi
fi

# ── Final hints ───────────────────────────────────────────────────────────────

echo ""
echo "==> Done!"
echo "    - bar widget:  omarchy plugin enable/disable $PLUGIN_ID, move with omarchy bar move"
echo "    - keybinding:  SUPER+Shift+V opens the VPN menu"
echo ""

# ── Interactive configuration ─────────────────────────────────────────────────

echo ""
echo "==> Configuration wizard"
python3 "$INSTALL_DIR/src/vpn_manager.py" --configure
