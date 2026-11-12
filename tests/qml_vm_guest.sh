#!/usr/bin/env bash
# DESTRUCTIVE inside the disposable guest only; never run on an ordinary desktop.
set -euo pipefail
if [[ ${OMARCHY_VPN_DISPOSABLE_GUEST:-} != 1 ]] \
    || ! grep -qw 'omarchy_vpn_test=1' /proc/cmdline \
    || ! systemd-detect-virt --vm >/dev/null; then
    echo "Refusing setup outside the explicitly marked disposable VM" >&2
    exit 64
fi

export OMARCHY_PATH=/usr/share/omarchy
export LANG=C.UTF-8 LC_ALL=C.UTF-8
OUT=/mnt/out
REPO=/mnt/repo
sudo -n true 2>/dev/null || printf 'omarchy\n' | sudo -S -v >/dev/null
sudo mkdir -p "$OUT" "$REPO"
sudo mount -t 9p -o trans=virtio,version=9p2000.L,ro repo "$REPO"
sudo mount -t 9p -o trans=virtio,version=9p2000.L out "$OUT"
sudo chown omarchy:omarchy "$OUT"
: > "$OUT/actions.log"
for _ in $(seq 1 300); do
    pgrep -x quickshell >/dev/null && break
    sleep 0.2
done
pgrep -x quickshell >/dev/null

# Deterministic vendor fixture: every non-read operation is logged AND refused.
tmp=$(mktemp)
cat > "$tmp" <<'VENDOR'
#!/bin/bash
case "${1:-}" in
    status)
        printf '%s\n' 'Login state: Logged in' 'Connect state: Disconnected' 'Firewall state: Off'
        ;;
    locations)
        for i in $(seq -w 1 201); do
            printf 'VM Region - City %s - Server %s (10 Gbps)\n' "$i" "$i"
        done
        ;;
    *) printf '%s\n' "$*" >> /mnt/out/actions.log; exit 1 ;;
esac
VENDOR
sudo install -m 755 "$tmp" /usr/local/bin/windscribe-cli
rm -f "$tmp"

# Stage only in the guest overlay; the repo share is read-only.
backend="$HOME/.local/share/omarchy-vpn"
plugin="$HOME/.config/omarchy/plugins/omarchy-vpn"
systemctl --user stop omarchy-vpn-backend.service 2>/dev/null || true
mkdir -p "$backend" "$plugin" "$HOME/.config/systemd/user"
rm -rf "$backend/src"
cp -a "$REPO/src" "$backend/src"
find "$plugin" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp "$REPO/manifest.json" "$REPO"/*.qml "$plugin/"
cp "$REPO/systemd/omarchy-vpn-backend.service" "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now omarchy-vpn-backend.service

# Test-only runtime inspection, added to the staged copy, NEVER to production
# QML. Observe the real TextField and rendered model; don't infer UI state from
# the Python backend. Select the fixture's provider cursor without assuming
# an incidental provider order or invoking any connection.
python3 - "$plugin/Widget.qml" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
anchor = '    function toggle(): void { root.toggle() }'
assert s.count(anchor) == 1
probe = '''
    function auditSnapshot(): string {
      return JSON.stringify({
        fieldText: root.activeList.filterField.text,
        appliedFilter: root.serverFilter,
        serverNames: root.serverRows.filter(function(r) { return r.kind === "server" })
          .map(function(r) { return r.server.name }),
        surface: root.windowOpen && !root.opened ? "window" : "panel",
        inactiveModelCount: root.windowOpen && !root.opened ? panelList.count : appWindow.locations.count,
        panelVisible: root.opened, windowVisible: root.windowOpen,
        panelCount: panelList.count, windowCount: appWindow.locations.count,
        panelText: panelList.filterField.text, windowText: appWindow.locations.filterField.text,
        panelNames: panelList.model.filter(function(r) { return r.kind === "server" })
          .map(function(r) { return r.server.name }),
        windowNames: appWindow.locations.model.filter(function(r) { return r.kind === "server" })
          .map(function(r) { return r.server.name })
      })
    }
    function auditSelectWindscribe(): void {
      for (var i = 0; i < root.serverRows.length; i++) {
        var r = root.serverRows[i]
        if (r.kind === "provider" && r.provider.name === "Windscribe") {
          root.serverCursor = i
          return
        }
      }
    }
'''
p.write_text(s.replace(anchor, anchor + probe))
PY
python3 - <<'PY'
import json
from pathlib import Path
p = Path.home()/'.config/omarchy/shell.json'
s = json.loads(p.read_text())
right = s.setdefault('bar', {}).setdefault('layout', {}).setdefault('right', [])
if not any(isinstance(r, dict) and r.get('id') == 'omarchy-vpn' for r in right):
    right.append({'id': 'omarchy-vpn'})
p.write_text(json.dumps(s) + '\n')
PY
sleep 5
start=$(date '+%Y-%m-%d %H:%M:%S')
trap 'journalctl --user --since "$start" --no-pager > "$OUT/shell-journal.txt" || true' EXIT
omarchy restart shell
sleep 3
export XDG_RUNTIME_DIR=/run/user/$(id -u)
WAYLAND_DISPLAY=$(find "$XDG_RUNTIME_DIR" -maxdepth 1 -type s -name 'wayland-*' -printf '%f\n' | head -1)
HYPRLAND_INSTANCE_SIGNATURE=$(find "$XDG_RUNTIME_DIR/hypr" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | head -1)
export WAYLAND_DISPLAY HYPRLAND_INSTANCE_SIGNATURE

snapshot() { omarchy-shell omarchy-vpn auditSnapshot > "$OUT/$1.json"; }
omarchy-shell omarchy-vpn open
sleep 2
omarchy-shell omarchy-vpn auditSelectWindscribe
wtype -k l
sleep 1
snapshot expanded
python3 - "$OUT/expanded.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert len(x['serverNames']) == 201, x
PY
for _ in $(seq 1 35); do wtype -k j; done
wtype '/'
wtype -d 50 'City 200'
snapshot typed-unapplied
wtype -k Return
sleep 1
snapshot panel-filtered
grim "$OUT/panel-filtered.png"
omarchy-shell omarchy-vpn window
sleep 1
snapshot window-filtered
grim "$OUT/window-filtered.png"
# Keep the window visible, then open the panel and apply a different filter.
# Both real models and both fields must update; neither visible surface may empty.
omarchy-shell omarchy-vpn open
sleep 1
wtype '/'
wtype -d 50 'City 199'
wtype -k Return
sleep 1
snapshot both-filtered
grim "$OUT/both-filtered.png"
omarchy-shell omarchy-vpn close
wtype -k Escape
journalctl --user --since "$start" --no-pager > "$OUT/shell-journal.txt"
python3 "$REPO/tests/qml_vm_verify.py" "$OUT"
printf 'PASS\n' > "$OUT/result.txt"
