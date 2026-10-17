import QtQuick
import QtQuick.Controls
import Quickshell
import qs.Commons
import qs.Ui

// The app window (SUPER+Shift+V, right click, `m` in the panel): a regular
// Hyprland window, like omarchy's dev gallery — Locations on the left,
// Connection + Tools on the right. Same state as the bar panel (`host` is the
// Widget), so the cursor, filter and pings carry over.
FloatingWindow {
  id: win
  property var host: null
  // the Widget scrolls this list while the window is open
  readonly property alias locations: locations

  // the old 🛠 Tools submenu, one button each (--tool KEY)
  readonly property var tools: [
    { key: "dns_leak_test", label: "DNS leak test" },
    { key: "ip_info", label: "IP info" },
    { key: "speed_test", label: "Speed test" },
    { key: "refresh_all", label: "Refresh subscriptions" },
    { key: "clear_caches", label: "Clear caches" },
    { key: "killswitch", label: "Kill switch on/off" },
    { key: "settings", label: "Settings" }
  ]

  title: "VPN"
  color: Color.background
  implicitWidth: 960
  implicitHeight: 640
  minimumSize: Qt.size(720, 480)
  visible: false  // Widget.openWindow() shows it; Esc or Hyprland's close hides it

  onVisibleChanged: if (visible) Qt.callLater(function() { keyCatcher.forceActiveFocus() })

  PanelKeyCatcher {
    id: keyCatcher
    anchors.fill: parent
    anchors.margins: Style.space(20)
    // typing in the filter must not drive the cursor (j/k/h/l are moves)
    blocked: locations.filterFocused
    onMoveRequested: function(dx, dy) {
      if (dy !== 0) win.host.moveServerCursor(dy)
      else win.host.openCursorGroup(dx > 0)
    }
    onActivateRequested: {
      if (win.host.serverCursor >= 0) win.host.activateServerRow(win.host.serverRows[win.host.serverCursor])
      else win.host.moveServerCursor(1)
    }
    onCloseRequested: win.visible = false
    onTextKey: function(t) {
      var k = String(t).toLowerCase()
      if (k === "t") win.host.togglePower()
      else if (k === "d") win.host.runDnsTest()
      else if (k === "r") { win.host.refresh(); win.host.loadServers() }
      else if (k === "p" && win.host.serverCursor >= 0) win.host.pingRow(win.host.serverRows[win.host.serverCursor])
      else if (k === "/") locations.filterField.forceActiveFocus()
      else if (k === "[") win.host.stepProvider(-1)
      else if (k === "]") win.host.stepProvider(1)
    }

    Row {
      id: columns
      anchors.top: parent.top
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.bottom: keyHints.top
      anchors.bottomMargin: Style.space(12)
      spacing: Style.space(24)

      // ── Locations: protocols as a tree (in the list), tabs or a sidebar ─
      Item {
        id: left
        readonly property string layout: win.host.windowLayout
        width: (columns.width - columns.spacing) * (layout === "sidebar" ? 0.65 : 0.55)
        height: columns.height

        ProviderSwitcher {
          id: sidebar
          visible: left.layout === "sidebar"
          vertical: true
          host: win.host
          width: visible ? Style.space(150) : 0
          anchors.top: parent.top
          anchors.bottom: parent.bottom
          anchors.left: parent.left
        }

        ProviderSwitcher {
          id: tabs
          visible: left.layout === "tabs"
          host: win.host
          height: visible ? implicitHeight : 0
          anchors.top: parent.top
          anchors.left: parent.left
          anchors.right: parent.right
        }

        Flickable {
          id: locationsFlick
          anchors.top: tabs.bottom
          anchors.topMargin: tabs.visible ? Style.space(12) : 0
          anchors.bottom: parent.bottom
          anchors.left: sidebar.right
          anchors.leftMargin: sidebar.visible ? Style.space(16) : 0
          anchors.right: parent.right
          contentWidth: width
          contentHeight: locations.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          ServerList {
            id: locations
            width: locationsFlick.width - Style.space(8)
            host: win.host
            flick: locationsFlick
            keyTarget: keyCatcher
          }
        }
      }

      // ── Connection + Tools ─────────────────────────────────────────────
      Flickable {
        id: sideFlick
        width: columns.width - columns.spacing - left.width
        height: columns.height
        contentWidth: width
        contentHeight: side.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick

        Column {
          id: side
          width: sideFlick.width
          spacing: Style.space(12)

          ConnectionSummary {
            width: parent.width
            host: win.host
          }

          PanelSeparator { foreground: win.host.foreground }

          PanelSectionHeader {
            text: "TOOLS"
            foreground: win.host.foreground
            fontFamily: win.host.fontFamily
          }

          Flow {
            width: parent.width
            spacing: Style.space(8)

            Repeater {
              // ⚙ Settings hides tools; no kill switch under a NetworkManager VPN
              // (panel_state's "tools"; all of them before the first status)
              model: win.tools.filter(function(t) {
                var keys = win.host.panelData.tools
                return !(keys instanceof Array) || keys.indexOf(t.key) !== -1
              })
              Button {
                required property var modelData
                text: modelData.label
                foreground: win.host.foreground
                fontFamily: win.host.fontFamily
                fontSize: Style.font.bodySmall
                bordered: true
                onClicked: win.host.runArgs(["--tool", modelData.key])
              }
            }
          }
        }
      }
    }

    Text {
      id: keyHints
      // ⚙ Settings → "Show key hints in the panel" (config panel_key_hints)
      visible: win.host.panelData.key_hints !== false
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.bottom: parent.bottom
      textFormat: Text.PlainText
      text: "j/k move · h/l fold · enter connect · p ping · / filter"
        + (win.host.windowLayout !== "tree" ? " · [ ] protocol" : "")
        + " · t toggle · d DNS · r refresh · esc close"
      color: win.host.dim
      font.family: win.host.fontFamily
      font.pixelSize: Style.font.caption
      horizontalAlignment: Text.AlignHCenter
    }
  }
}
