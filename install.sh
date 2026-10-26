#!/usr/bin/env bash
set -e
# Finish setup's terminal (omarchy-launch-floating-terminal-with-presentation)
# prints "Done!" whatever the exit code: a failed step has to say so itself.
# ERR, not EXIT: the wizard's cancel is an explicit exit with its own message.
trap 'echo "==> Setup failed — see the error above. Fix it and run setup again." >&2' ERR

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

# ── Questions (before any sudo) ───────────────────────────────────────────────
# Detects what's installed, asks protocols/features (preselected), saves
# config.json and writes the packages still missing to fd 3 (PKG_FILE; the
# env marker tells it fd 3 is ours).
# -B: nothing may be written under the plugin dir (hot reload).

PKG_FILE=$(mktemp)
trap 'rm -f "$PKG_FILE"' EXIT
OMARCHY_VPN_WIZARD_FD=3 python3 -B "$REPO_DIR/src/vpn_manager.py" --install-wizard 3>"$PKG_FILE" || {
    echo "==> Cancelled — nothing changed."
    exit 1
}
mapfile -t MISSING < "$PKG_FILE"
# the wizard's last line after a yes to "Switch DNS to systemd-resolved?"
SWITCH_RESOLVCONF=""
if [[ ${#MISSING[@]} -gt 0 && ${MISSING[-1]} == ":resolv-stub" ]]; then
    SWITCH_RESOLVCONF=1
    MISSING=("${MISSING[@]:0:${#MISSING[@]}-1}")
fi

# ── Dependencies ──────────────────────────────────────────────────────────────

echo ""
echo "==> Root steps: packages, helpers, sudoers rule"
sudo -v

# openresolv (left by an older install.sh) conflicts with systemd-resolvconf, and
# --noconfirm answers "no" to removing a conflicting package. Not one transaction:
# if pacman -S fails after this, a re-run asks again and finishes the switch.
if [[ -n $SWITCH_RESOLVCONF ]] && pacman -Q openresolv 2>/dev/null | grep -q "^openresolv "; then
    echo "==> Replacing openresolv with systemd-resolvconf..."
    sudo pacman -R --noconfirm openresolv
fi

if (( ${#MISSING[@]} )); then
    echo "==> Installing: ${MISSING[*]}"
    sudo pacman -S --needed --noconfirm "${MISSING[@]}"
else
    echo "==> All packages already installed"
fi

if [[ -n $SWITCH_RESOLVCONF ]]; then
    echo "==> /etc/resolv.conf -> systemd-resolved's stub"
    sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi

# ── sudoers rule ──────────────────────────────────────────────────────────────

SUDOERS_FILE="/etc/sudoers.d/vpn-manager"
# Managed by this installer: rewrite on every run so upgrades pick up new rules.
# Three things only, each with a fixed command surface:
#   omarchy-vpn-helper (scripts/, root-owned): WireGuard/AmneziaWG/OpenVPN up/down,
#     import, delete, autostart, endpoints — profile names only, never paths, and
#     it refuses imports that could run commands as root (WireGuard PostUp/…,
#     OpenVPN directives off its allowlist: up/route-up/plugin/…);
#   happ-killswitch (root-owned): the kill switch's nft rules;
#   sysctl -w net.ipv6.conf.{all,default}.disable_ipv6={0,1} (IPv6 leak guard —
#     none of the providers tunnel IPv6, see src/ipv6guard.py).
# It used to grant `wg-quick *`, `cp * /etc/wireguard/*`, `cat /etc/wireguard/*`,
# `kill` and `openvpn --config *` — sudoers' `*` spans `/` and `..`, and a PostUp
# line runs as root, so every process running as the user had passwordless root
# (and could read the private keys). plugins.omarchy.org's scanner blocks that.
# openvpn-dns-updown (root-owned) applies OpenVPN-pushed DNS via systemd-resolved;
# openvpn runs as root, so its --up/--down child needs no entry of its own.
# the helper first: a rule pointing at a missing (or old) helper breaks connects
echo "==> Installing omarchy-vpn-helper to /usr/local/bin..."
sudo cp "$REPO_DIR/scripts/omarchy-vpn-helper" /usr/local/bin/omarchy-vpn-helper
sudo chown root:root /usr/local/bin/omarchy-vpn-helper
sudo chmod 755 /usr/local/bin/omarchy-vpn-helper

echo "==> Writing sudoers rule..."
echo "$USER ALL=(root) NOPASSWD: /usr/local/bin/omarchy-vpn-helper, /usr/local/bin/happ-killswitch, /usr/bin/sysctl -w net.ipv6.conf.all.disable_ipv6=1, /usr/bin/sysctl -w net.ipv6.conf.all.disable_ipv6=0, /usr/bin/sysctl -w net.ipv6.conf.default.disable_ipv6=1, /usr/bin/sysctl -w net.ipv6.conf.default.disable_ipv6=0" \
    | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE" > /dev/null && echo "==> sudoers rule validated"

# Imports refuse root hooks, but `up` still runs configs already on disk —
# some may predate the helper (the old rule let any process `cp` one there).
unsafe_configs=$(sudo /usr/local/bin/omarchy-vpn-helper audit)
if [[ -n $unsafe_configs ]]; then
    echo "==> WARNING: these VPN configs have lines an import would refuse (root commands or file reads):"
    echo "$unsafe_configs" | sed 's/^/      /'
    echo "    Remove those lines unless you put them there yourself."
fi

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

# ── Backend ───────────────────────────────────────────────────────────────────

echo "==> Installing backend to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/src"
cp -r "$REPO_DIR/src" "$INSTALL_DIR/"
# the widget compares it with its plugin dir's HEAD after `omarchy plugin update`
git -C "$REPO_DIR" rev-parse HEAD > "$INSTALL_DIR/installed-commit" 2>/dev/null \
    || rm -f "$INSTALL_DIR/installed-commit"
# autostarted WireGuard tunnels come up before login: a drop-in turns IPv6 off
# first (⚙ IPv6 guard) — profiles whose autostart predates this release too
python3 "$INSTALL_DIR/src/vpn_manager.py" --ipv6-boot-sync || echo "    (re-run later: python3 $INSTALL_DIR/src/vpn_manager.py --ipv6-boot-sync)"

# ── omarchy-shell bar widget ──────────────────────────────────────────────────

# `omarchy plugin add` clones this repo into $PLUGIN_DIR and the panel's
# Finish setup runs this script from there: nothing to copy then.
if [[ "$REPO_DIR" -ef "$PLUGIN_DIR" ]]; then
    echo "==> Bar widget: running from $PLUGIN_DIR (omarchy plugin add)"
else
    echo "==> Installing bar widget to $PLUGIN_DIR..."
    mkdir -p "$PLUGIN_DIR"
    cp "$REPO_DIR/manifest.json" "$REPO_DIR"/*.qml "$PLUGIN_DIR/"
fi
omarchy-shell -q shell rescanPlugins
if ! omarchy plugin list | grep -qE "^${PLUGIN_ID}[[:space:]]+enabled"; then
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
o.window({ class = "^org.quickshell$", title = "^VPN( Check)?$" }, { tag = "+floating-window" })
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
        echo "    Reconnect from the bar panel, then run 'make install' again to remove it."
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
echo "    - keybinding:  SUPER+Shift+V opens the VPN window"
echo "    - settings:    the window's Settings button, or re-run this installer"
echo ""
