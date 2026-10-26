#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ID="omarchy-vpn"
PLUGIN_DIR="$HOME/.config/omarchy/plugins/$PLUGIN_ID"

# Kill switch first: Lockdown's nft rules outlive the plugin, so they go (checked gone)
# before anything is removed — a failure there leaves the install intact.
[[ ! -x /usr/local/bin/happ-killswitch ]] || sudo /usr/local/bin/happ-killswitch off
if sudo nft list table inet happ-ks >/dev/null 2>&1; then
    echo "kill switch rules still active — nothing removed" >&2
    exit 1
fi
omarchy plugin disable "$PLUGIN_ID" || true
# a clone from `omarchy plugin add` is removed with `omarchy plugin remove`
[[ "$REPO_DIR" -ef "$PLUGIN_DIR" ]] || rm -rf "$PLUGIN_DIR"
omarchy-shell -q shell rescanPlugins || true
rm -rf "$HOME/.local/share/omarchy-vpn"
sed -i '/^-- >>> omarchy-vpn$/,/^-- <<< omarchy-vpn$/d' "$HOME/.config/hypr/bindings.lua" 2>/dev/null || true
sudo rm -f /usr/local/bin/happ-killswitch /usr/local/bin/openvpn-dns-updown /usr/local/bin/omarchy-vpn-helper
rm -f "$HOME/.config/happ-killswitch.conf"
sudo rm -f /etc/sudoers.d/vpn-manager
echo "Uninstalled."
if [[ "$REPO_DIR" -ef "$PLUGIN_DIR" ]]; then
    echo "Now remove the plugin itself: omarchy plugin remove $PLUGIN_ID"
fi
