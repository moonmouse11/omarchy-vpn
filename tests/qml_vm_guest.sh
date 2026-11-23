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
python3 "$REPO/tests/windscribe_handover_probe.py" \
    --output "$OUT/windscribe-handover.json"
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

# Deterministic hostile clipboard transfers. Normal mode still delegates to
# the real Wayland wl-paste; the other modes exercise the same production
# Python reader without trusting a compositor-specific malicious owner.
tmp=$(mktemp)
cat > "$tmp" <<'CLIPBOARD'
#!/bin/bash
case "$(cat /tmp/omarchy-vpn-wl-paste-mode 2>/dev/null || true)" in
    oversize) python3 -c 'import os; os.write(1, b"x" * 4097)' ;;
    stall) sleep 60 ;;
    delay) sleep 1; exec /usr/bin/wl-paste "$@" ;;
    *) exec /usr/bin/wl-paste "$@" ;;
esac
CLIPBOARD
sudo install -m 755 "$tmp" /usr/local/bin/wl-paste
rm -f "$tmp"
printf 'normal\n' > /tmp/omarchy-vpn-wl-paste-mode

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
handler = '  IpcHandler {\n    target: root.ipcTarget'
launch = '    connectProc.running = true'
assert s.count(anchor) == 1
assert s.count(handler) == 1
assert s.count(launch) == 1
s = s.replace(
    handler,
    '  Connections {\n'
    '    target: panelList\n'
    '    function onContentYChanged() {\n'
    '      if (auditIpc.auditTrackViewport)\n'
    '        auditIpc.auditPanelY = auditIpc.auditPanelY.concat([{ y: panelList.contentY, at: Date.now() }])\n'
    '    }\n'
    '  }\n\n'
    '  IpcHandler {\n    id: auditIpc\n    target: root.ipcTarget',
)
s = s.replace(
    launch,
    '    if (auditIpc.auditCapture) {\n'
    '      auditIpc.auditCommands = auditIpc.auditCommands.concat([args])\n'
    '      return\n'
    '    }\n'
    + launch,
)
probe = '''
    property bool auditCapture: false
    property var auditCommands: []
    property bool auditTrackViewport: false
    property var auditPanelY: []
    property string auditRaceExpectedKey: ""
    property string auditRequestedBarLabel: ""
    function auditListNames(list): var {
      var names = []
      for (var i = 0; i < list.count; i++) {
        var row = root.serverRows[i]
        if (row && row.kind === "server") names.push(row.server.name)
      }
      return names
    }
    function auditTopRow(list): var {
      var best = null
      for (var i = 0; i < list.count; i++) {
        var item = list.itemAtIndex(i)
        if (!item || item.y + item.height <= list.contentY || item.y >= list.contentY + list.height)
          continue
        if (!best || item.y < best.y)
          best = { key: root.rowIdentity(root.serverRows[i]), offset: item.y - list.contentY, y: item.y }
      }
      return best || { key: "", offset: 0, y: 0 }
    }
    function auditSnapshot(): string {
      var top = auditTopRow(root.activeList)
      var panelTop = auditTopRow(panelList)
      var windowTop = auditTopRow(appWindow.locations)
      var cursorItem = root.activeList.itemAtIndex(root.serverCursor)
      return JSON.stringify({
        fieldText: root.activeList.filterField.text,
        filterFocused: root.activeList.filterFocused,
        appliedFilter: root.serverFilter,
        serverNames: root.serverRows.filter(function(r) { return r.kind === "server" })
          .map(function(r) { return r.server.name }),
        surface: root.windowOpen && !root.opened ? "window" : "panel",
        inactiveModelCount: root.windowOpen && !root.opened ? panelList.count : appWindow.locations.count,
        panelVisible: root.opened, windowVisible: root.windowOpen,
        panelCount: panelList.count, windowCount: appWindow.locations.count,
        panelText: panelList.filterField.text, windowText: appWindow.locations.filterField.text,
        panelNames: auditListNames(panelList),
        windowNames: auditListNames(appWindow.locations),
        forceConfirmOpen: root.forceConfirmOpen,
        forceTarget: root.forceTarget,
        activeContentY: root.activeList.contentY,
        topKey: top.key,
        topOffset: top.offset,
        cursorKey: root.serverCursor >= 0 ? root.rowIdentity(root.serverRows[root.serverCursor]) : "",
        cursorOffset: cursorItem ? cursorItem.y - root.activeList.contentY : null,
        panelContentY: panelList.contentY,
        panelTopKey: panelTop.key,
        panelTopOffset: panelTop.offset,
        windowContentY: appWindow.locations.contentY,
        windowTopKey: windowTop.key,
        windowTopOffset: windowTop.offset,
        raceExpectedKey: auditRaceExpectedKey,
        panelYTrace: auditPanelY,
        panelDelegateCreates: panelList.auditDelegateCreates,
        requestedBarLabel: auditRequestedBarLabel,
        liveBarLabel: root.barLabel,
        displayedBarLabel: root.displayedBarLabel,
        barButtonWidth: button.width,
        panelCardX: panel.cardOrigin.x,
        panelContentWidth: panel.contentWidth,
        commands: auditCommands
      })
    }
    function auditStartForce(): void {
      auditCommands = []
      auditCapture = true
      root.connectServer("WireGuard", "vm-target", "sub-42")
      root.connectResult(JSON.stringify({
        success: false,
        message: "Windscribe did not confirm disconnect",
        action: "force-windscribe"
      }))
    }
    function auditResetForce(): void {
      root.cancelForceSwitch()
      auditCommands = []
      auditCapture = false
    }
    function auditOpenUrlPaste(): void {
      root.close()
      root.openWindow()
      root.closeProfileBar()
      root.checkKind = "speed"
      root.checkTarget = ""
      root.checkPhase = "choose"
      root.checkOpen = true
      Qt.callLater(function() {
        Qt.callLater(function() {
          appWindow.auditUrlInput.text = ""
          appWindow.auditUrlInput.forceActiveFocus()
        })
      })
    }
    function auditFocusUrlPaste(): void {
      appWindow.auditUrlInput.forceActiveFocus()
    }
    function auditUrlSnapshot(): string {
      return JSON.stringify({
        urlText: appWindow.auditUrlInput.text,
        urlFocused: appWindow.auditUrlInput.activeFocus
      })
    }
    function auditOpenKeyPaste(): void {
      root.checkOpen = false
      root.startImport({
        name: "VLESS",
        importer: "key",
        group: { provider: "VLESS" },
        server: { active: false }
      })
      Qt.callLater(function() {
        Qt.callLater(function() {
          appWindow.auditProfileInput.text = ""
          appWindow.auditProfileInput.forceActiveFocus()
        })
      })
    }
    function auditKeySnapshot(): string {
      return JSON.stringify({
        keyLength: appWindow.auditProfileInput.text.length,
        keyMasked: appWindow.auditProfileInput.password,
        keyFocused: appWindow.auditProfileInput.activeFocus
      })
    }
    function auditSelectWindscribe(): void {
      for (var i = 0; i < root.serverRows.length; i++) {
        var r = root.serverRows[i]
        if (r.kind === "provider" && r.provider.name === "Windscribe") {
          root.serverCursor = i
          root.activeList.scrollToRow(i)
          return
        }
      }
    }
    function auditPrepareBothViewports(): void {
      root.serverFilter = ""
      root.setExpanded("provider:Windscribe", true, null)
      Qt.callLater(function() {
        Qt.callLater(function() {
          panelList.positionViewAtIndex(12, ListView.Beginning)
          appWindow.locations.positionViewAtIndex(40, ListView.Beginning)
        })
      })
    }
    function auditSetBarLabel(value: string): void {
      auditRequestedBarLabel = value
      var next = {}
      for (var key in root.panelData) next[key] = root.panelData[key]
      var fields = {}
      var current = root.panelData.fields || {}
      for (var field in current) fields[field] = current[field]
      fields.label = value
      fields.server = value
      fields.state = value
      next.fields = fields
      root.connected = true
      root.label = value
      root.panelData = next
    }
    function auditPrimeBarLabel(value: string): void {
      auditSetBarLabel(value)
      root.panelBarLabel = value
      root.panelBarLabelCaptured = true
    }
    function auditStartViewportTrace(): void {
      auditPanelY = [{ y: panelList.contentY, at: Date.now() }]
      auditTrackViewport = true
      panelList.auditDelegateCreates = 0
      panelList.auditCountDelegates = true
      root.loadServers()
    }
    function auditStopViewportTrace(): void {
      auditTrackViewport = false
      panelList.auditCountDelegates = false
    }
    function auditStartRestoreRace(): void {
      panelList.positionViewAtIndex(20, ListView.Beginning)
      Qt.callLater(function() {
        root.rememberViewports()
        root.serverGroups = root.serverGroups.slice()
        Qt.callLater(function() {
          panelList.positionViewAtIndex(80, ListView.Beginning)
          auditRaceExpectedKey = root.rowIdentity(root.serverRows[80])
          root.rememberViewports()
          root.serverProviders = root.serverProviders.slice()
        })
      })
    }
'''
p.write_text(s.replace(anchor, anchor + probe))
server_list = p.with_name('ServerList.qml')
sl = server_list.read_text()
list_anchor = 'ListView {\n  id: list'
delegate_anchor = '    required property int index'
assert sl.count(list_anchor) == 1
assert sl.count(delegate_anchor) == 1
sl = sl.replace(
    list_anchor,
    list_anchor
    + '\n  property bool auditCountDelegates: false'
    + '\n  property int auditDelegateCreates: 0'
    + '\n  function auditDelegateCreated() {'
    + '\n    if (auditCountDelegates) auditDelegateCreates++'
    + '\n  }',
)
sl = sl.replace(
    delegate_anchor,
    delegate_anchor + '\n    Component.onCompleted: list.auditDelegateCreated()',
)
server_list.write_text(sl)
profile_bar = p.with_name('ProfileBar.qml')
pb = profile_bar.read_text()
profile_anchor = 'Column {\n  id: bar'
assert pb.count(profile_anchor) == 1
profile_bar.write_text(pb.replace(
    profile_anchor,
    profile_anchor + '\n  readonly property alias auditInput: input',
))
check_card = p.with_name('CheckCard.qml')
cc = check_card.read_text()
check_anchor = 'Item {\n  id: card'
assert cc.count(check_anchor) == 1
check_card.write_text(cc.replace(
    check_anchor,
    check_anchor + '\n  readonly property alias auditUrlInput: urlField',
))
app_window = p.with_name('AppWindow.qml')
aw = app_window.read_text()
window_anchor = '  readonly property alias locations: locations'
assert aw.count(window_anchor) == 1
app_window.write_text(aw.replace(
    window_anchor,
    window_anchor
    + '\n  readonly property alias auditProfileInput: profileBar.auditInput'
    + '\n  readonly property alias auditUrlInput: checkCard.auditUrlInput',
))
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
# Real Ctrl+V on the stable filter field through a real Wayland clipboard.
wtype '/'
printf '%s' 'City 198' | wl-copy --type text/plain >/dev/null 2>&1
wtype -M ctrl -k v -m ctrl
sleep 1
snapshot paste-valid
wtype -M ctrl -k a -m ctrl -k BackSpace
# The hostile transfer exceeds the filter's 4 KiB backend preset; no partial
# text may reach Qt and the field must keep focus.
printf 'oversize\n' > /tmp/omarchy-vpn-wl-paste-mode
wtype -M ctrl -k v -m ctrl
sleep 1
snapshot paste-oversize
# A silent transfer consumes the reader's one two-second deadline. The next
# Shift+Insert must still work, proving recovery rather than a wedged Process.
printf 'stall\n' > /tmp/omarchy-vpn-wl-paste-mode
wtype -M ctrl -k v -m ctrl
sleep 3
snapshot paste-timeout
printf 'normal\n' > /tmp/omarchy-vpn-wl-paste-mode
printf '%s' 'City 197' | wl-copy --type text/plain >/dev/null 2>&1
wtype -M shift -k Insert -m shift
sleep 1
snapshot paste-recovered
wtype -M ctrl -k a -m ctrl -k BackSpace
omarchy-shell omarchy-vpn auditStartForce
sleep 1
snapshot force-panel-open
wtype -k Escape
sleep 1
snapshot force-panel-cancelled
omarchy-shell omarchy-vpn auditSelectWindscribe
sleep 1
snapshot windscribe-selected
wtype -k l
sleep 1
snapshot expanded
grim "$OUT/panel-expanded.png"
python3 - "$OUT/expanded.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert len(x['serverNames']) == 202, x
assert x['serverNames'][0] == 'Best Location', x
PY
wtype -k h
sleep 1
snapshot folded
grim "$OUT/panel-folded.png"
python3 - "$OUT/folded.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert not x['serverNames'], x
PY
wtype -k l
sleep 1
snapshot reexpanded
python3 - "$OUT/reexpanded.json" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
assert len(x['serverNames']) == 202, x
PY
for _ in $(seq 1 35); do wtype -k j; done
sleep 1
snapshot panel-scrolled-before-refresh
grim "$OUT/panel-scrolled.png"
omarchy-shell omarchy-vpn auditStartViewportTrace
sleep 2
snapshot panel-scrolled-after-refresh
omarchy-shell omarchy-vpn auditStopViewportTrace
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
omarchy-shell omarchy-vpn auditStartForce
sleep 1
snapshot force-window-open
wtype -k Return
sleep 1
snapshot force-window-confirmed
omarchy-shell omarchy-vpn auditResetForce
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
omarchy-shell omarchy-vpn auditPrepareBothViewports
sleep 1
snapshot both-scrolled-before-refresh
omarchy-shell omarchy-vpn refresh
sleep 2
snapshot both-scrolled-after-refresh
omarchy-shell omarchy-vpn auditPrimeBarLabel DE
snapshot bar-label-short
omarchy-shell omarchy-vpn auditSetBarLabel Netherlands-with-a-much-longer-name
snapshot bar-label-long
omarchy-shell omarchy-vpn auditStartRestoreRace
sleep 2
snapshot restore-race

# Exercise the other two reviewed fields without screenshots containing the
# masked key. Both still use real keyboard shortcuts and Wayland clipboard.
omarchy-shell omarchy-vpn auditOpenUrlPaste
sleep 1
omarchy-shell omarchy-vpn auditFocusUrlPaste
sleep 1
printf '%s' 'https://example.com/vm.bin' | wl-copy --type text/plain >/dev/null 2>&1
wtype -M ctrl -k v -m ctrl
sleep 1
omarchy-shell omarchy-vpn auditUrlSnapshot > "$OUT/paste-url.json"

omarchy-shell omarchy-vpn auditOpenKeyPaste
sleep 1
secret='vless://vm-secret-DO-NOT-LEAK@example.com:443?type=tcp'
printf '%s' "$secret" | wl-copy --type text/plain >/dev/null 2>&1
printf 'delay\n' > /tmp/omarchy-vpn-wl-paste-mode
wtype -M shift -k Insert -m shift
for _ in $(seq 1 20); do
    pgrep -af -- 'vpn_manager.py --clipboard key' >/dev/null && break
    sleep 0.05
done
python3 - "$OUT/paste-process.json" <<'PY'
import json
from pathlib import Path
import sys

marker = b"vm-secret-DO-NOT-LEAK"
seen = False
leaked = False
for path in Path("/proc").glob("[0-9]*/cmdline"):
    try:
        command = path.read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    args = command.split(b"\0")
    if b"--clipboard" in args and b"key" in args:
        seen = True
    if marker in command:
        leaked = True
Path(sys.argv[1]).write_text(json.dumps({
    "clipboardProcessSeen": seen,
    "secretInArgv": leaked,
}))
PY
sleep 2
omarchy-shell omarchy-vpn auditKeySnapshot > "$OUT/paste-key.json"
printf 'normal\n' > /tmp/omarchy-vpn-wl-paste-mode
pkill -x wl-copy 2>/dev/null || true
wtype -k Escape

python3 - "$OUT" <<'PY'
import json
from pathlib import Path
import sys

out = Path(sys.argv[1])
read = lambda name: json.loads((out / f"{name}.json").read_text())
valid = read("paste-valid")
oversize = read("paste-oversize")
timed_out = read("paste-timeout")
recovered = read("paste-recovered")
url = read("paste-url")
key = read("paste-key")
process = read("paste-process")
evidence = {
    "paste_valid": valid.get("fieldText") == "City 198",
    "paste_oversize_rejected": oversize.get("fieldText") == "",
    "paste_timeout_recovered": timed_out.get("fieldText") == "" and recovered.get("fieldText") == "City 197",
    "paste_focus_retained": all(x.get("filterFocused") is True for x in (valid, oversize, timed_out, recovered)),
    "paste_secret_not_in_argv": process == {"clipboardProcessSeen": True, "secretInArgv": False},
    "paste_url_field": url == {"urlText": "https://example.com/vm.bin", "urlFocused": True},
    "paste_key_masked": key.get("keyLength", 0) >= 16 and key.get("keyMasked") is True and key.get("keyFocused") is True,
}
(out / "paste-evidence.json").write_text(json.dumps(evidence))
PY
omarchy-shell omarchy-vpn close
wtype -k Escape
journalctl --user --since "$start" --no-pager > "$OUT/shell-journal.txt"
python3 "$REPO/tests/qml_vm_verify.py" "$OUT"
printf 'PASS\n' > "$OUT/result.txt"
