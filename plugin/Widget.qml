import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Bar widget for omarchy-vpn. All VPN logic stays in the Python backend
// (installed to ~/.local/share/omarchy-vpn, NOT under this plugin dir — the
// shell hot-reloads plugins on any write here, __pycache__ included):
//   --status  Waybar-style JSON {text, tooltip, class}, polled every `interval`
//   --menu    the omarchy.menu-driven VPN menu
// The backend calls `omarchy-shell -q omarchy-vpn refresh` after every
// connect/disconnect, so the widget updates at once instead of on the next tick.
BarWidget {
  id: root
  moduleName: "omarchy-vpn"

  readonly property string backend: String(setting("backend",
    Quickshell.env("HOME") + "/.local/share/omarchy-vpn/src/vpn_manager.py"))
  readonly property bool showLabel: setting("showLabel", true) !== false

  property bool connected: false
  property string label: ""
  property string tooltip: "VPN"
  property bool refreshPending: false

  function refresh() {
    if (statusProc.running) {
      refreshPending = true
      return
    }
    statusProc.running = true
  }

  function openMenu() {
    Quickshell.execDetached(["python3", root.backend, "--menu"])
  }

  function update(raw) {
    var data = null
    try { data = JSON.parse(String(raw || "")) } catch (e) {}
    if (!data || typeof data !== "object") {
      connected = false
      label = ""
      tooltip = "VPN: backend not responding\n" + root.backend
      return
    }
    var klass = data["class"]
    var classes = Array.isArray(klass) ? klass : [String(klass || "")]
    connected = classes.indexOf("vpn-connected") !== -1
    label = connected ? String(data.text || "").trim() : ""
    tooltip = String(data.tooltip || "VPN")
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  IpcHandler {
    target: "omarchy-vpn"

    function refresh(): void { root.broadcast("refresh") }
    function menu(): void { root.openMenu() }
  }

  Process {
    id: statusProc
    command: ["python3", root.backend, "--status"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.update(text)
    }
    onExited: {
      if (!root.refreshPending) return
      root.refreshPending = false
      Qt.callLater(root.refresh)
    }
  }

  Timer {
    interval: Math.max(1, Number(root.setting("interval", 3))) * 1000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    // nf-fa-lock / nf-fa-unlock
    text: (root.connected ? "" : "")
      + (root.showLabel && root.label !== "" && !root.vertical ? "  " + root.label : "")
    tooltipText: root.tooltip
    dimmed: !root.connected
    fontSize: Style.font.caption
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) root.refresh()
      else root.openMenu()
    }
  }
}
