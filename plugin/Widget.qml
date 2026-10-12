import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Bar widget + panel for omarchy-vpn. All VPN logic stays in the Python backend
// (installed to ~/.local/share/omarchy-vpn, NOT under this plugin dir — the
// shell hot-reloads plugins on any write here, __pycache__ included):
//   --status          JSON {text, tooltip, class, panel}, polled every `interval`;
//                     `panel` = hero (title/meta/detail/rate) + protection badges
//   --menu            the omarchy.menu-driven VPN menu (servers, tools, settings)
//   --disconnect-all  the hero switch, when on
//   --dns-leak-test   the DNS badge, when not yet green
// The backend calls `omarchy-shell -q omarchy-vpn refresh` after every
// connect/disconnect, so the widget updates at once instead of on the next tick.
Panel {
  id: root
  moduleName: "omarchy-vpn"
  ipcTarget: "omarchy-vpn"
  manageIpc: false

  readonly property string backend: String(setting("backend",
    Quickshell.env("HOME") + "/.local/share/omarchy-vpn/src/vpn_manager.py"))
  readonly property bool showLabel: setting("showLabel", true) !== false
  readonly property bool vertical: bar ? bar.vertical : false

  property bool connected: false
  property string label: ""
  property string tooltip: "VPN"
  property var panelData: ({})
  property bool refreshPending: false
  property bool busy: false

  readonly property var badges: panelData && panelData.badges instanceof Array ? panelData.badges : []
  // protected | unverified | at_risk | off | blocked — the lock only once
  // every check has passed (vpn_manager.panel_state)
  readonly property string protectionState: String(panelData.state || (connected ? "unverified" : "off"))
  readonly property bool atRisk: protectionState === "at_risk"
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  // nf-fa-lock / nf-fa-warning / nf-fa-question / nf-fa-unlock — escaped:
  // private-use glyphs don't survive every editor/tool round trip as literals
  readonly property string stateGlyph: protectionState === "protected" ? "\uf023"
    : (protectionState === "at_risk" ? "\uf071"
    : (protectionState === "unverified" ? "\uf128" : "\uf09c"))
  // Two short lines under the hero: one long line got cut off at the
  // panel's width once the session totals joined the speed.
  readonly property string exitLine: panelData.exit_ip ? "Exit " + panelData.exit_ip : ""
  readonly property string trafficLine: {
    var parts = []
    if (panelData.rate) parts.push(panelData.rate)
    if (panelData.total) parts.push(panelData.total + " total")
    return parts.join("  ·  ")
  }
  // Hover: state + connection, exit + speed, and — only when not
  // Protected — which checks are missing or failed. The panel holds the rest.
  readonly property string hoverText: {
    if (!connected) return String(panelData.title || "Not protected") + " — click for details"
    var lines = [String(panelData.title || "VPN") + (panelData.meta ? " · " + panelData.meta : "")]
    var traffic = []
    if (panelData.exit_ip) traffic.push("Exit " + panelData.exit_ip)
    if (panelData.rate) traffic.push(panelData.rate)
    if (traffic.length > 0) lines.push(traffic.join(" · "))
    if (protectionState !== "protected") {
      var issues = []
      for (var i = 0; i < badges.length; i++)
        if (badges[i].id !== "killswitch" && badges[i].state !== "ok") issues.push(badges[i].label)
      if (issues.length > 0) lines.push(issues.join(" · "))
    }
    return lines.join("\n")
  }

  function refresh() {
    if (statusProc.running) {
      refreshPending = true
      return
    }
    statusProc.running = true
  }

  function run(flag) {
    Quickshell.execDetached(["python3", root.backend, flag])
  }

  function openMenu() {
    close()
    run("--menu")
  }

  // The switch: off disconnects everything; on has no "last server" to go
  // back to yet, so it opens the server menu.
  function togglePower() {
    if (connected) {
      busy = true
      run("--disconnect-all")
    } else {
      openMenu()
    }
  }

  function runDnsTest() {
    close()
    run("--dns-leak-test")
  }

  // Shape carries the state, colour only reinforces it: many themes have a
  // grey accent, and "ok" vs "unknown" must still read at a glance.
  function badgeGlyph(state) {
    if (state === "ok") return "\uf00c"     // nf-fa-check
    if (state === "bad") return "\uf071"    // nf-fa-warning
    return "\uf128"                          // nf-fa-question
  }

  function badgeColor(state) {
    if (state === "ok") return root.foreground
    if (state === "bad") return root.urgent
    return root.dim
  }

  function update(raw) {
    var data = null
    try { data = JSON.parse(String(raw || "")) } catch (e) {}
    busy = false
    if (!data || typeof data !== "object") {
      connected = false
      label = ""
      tooltip = "VPN: backend not responding\n" + root.backend
      panelData = { title: "Backend not responding", meta: root.backend, badges: [] }
      return
    }
    var klass = data["class"]
    var classes = Array.isArray(klass) ? klass : [String(klass || "")]
    connected = classes.indexOf("vpn-connected") !== -1
    label = connected ? String(data.text || "").trim() : ""
    tooltip = String(data.tooltip || "VPN")
    panelData = data.panel && typeof data.panel === "object" ? data.panel : {}
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  IpcHandler {
    target: root.ipcTarget

    function refresh(): void { root.refresh() }
    function menu(): void { root.openMenu() }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
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
    text: root.stateGlyph
      + (root.showLabel && root.label !== "" && !root.vertical ? "  " + root.label : "")
    tooltipText: root.opened ? "" : root.hoverText
    dimmed: !root.connected
    fontSize: Style.font.caption
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.MiddleButton) root.refresh()
      else if (buttonCode === Qt.RightButton) root.openMenu()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onActivateRequested: root.openMenu()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        var k = String(t).toLowerCase()
        if (k === "t") root.togglePower()
        else if (k === "m") root.openMenu()
        else if (k === "d") root.runDnsTest()
        else if (k === "r") root.refresh()
      }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(12)

        Item {
          id: header
          width: parent.width
          implicitHeight: hero.implicitHeight

          PanelHero {
            id: hero
            width: parent.width
            title: String(root.panelData.title || "VPN")
            meta: String(root.panelData.meta || "")
            detail: String(root.panelData.detail || "")
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconComponent: Component {
              Text {
                text: root.stateGlyph
                color: root.atRisk ? root.urgent : (root.connected ? root.foreground : root.dim)
                font.family: root.fontFamily
                font.pixelSize: Style.font.display
              }
            }
            trailingControl: Component {
              ToggleSwitch {
                id: powerSwitch
                checked: root.connected
                busy: root.busy
                foreground: hero.foreground
                onToggled: root.togglePower()

                PanelToolTip {
                  visible: powerSwitch.containsMouse
                  text: root.connected ? "Disconnect all VPNs" : "Choose a server"
                  fontFamily: hero.fontFamily
                }
              }
            }
          }
        }

        Text {
          textFormat: Text.PlainText
          visible: text !== ""
          width: parent.width
          text: root.exitLine
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }

        Text {
          textFormat: Text.PlainText
          visible: text !== ""
          width: parent.width
          text: root.trafficLine
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        PanelSeparator { foreground: root.foreground }

        PanelSectionHeader {
          text: "PROTECTION"
          foreground: root.foreground
          fontFamily: root.fontFamily
        }

        Flow {
          width: parent.width
          spacing: Style.space(8)

          Repeater {
            model: root.badges

            BorderSurface {
              id: badge
              required property var modelData
              readonly property bool actionable: modelData.id === "dns" && modelData.state !== "ok"
              implicitWidth: badgeRow.implicitWidth + Style.space(16)
              implicitHeight: badgeRow.implicitHeight + Style.space(8)
              color: badgeMouse.containsMouse && actionable
                ? Style.hoverFillFor(root.foreground, Color.accent) : "transparent"
              borderSpec: Border.controlSpec("normal", root.badgeColor(modelData.state), root.badgeColor(modelData.state))
              radius: Style.cornerRadius

              Row {
                id: badgeRow
                anchors.centerIn: parent
                spacing: Style.space(6)

                Text {
                  text: root.badgeGlyph(badge.modelData.state)
                  color: root.badgeColor(badge.modelData.state)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.caption
                  anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                  textFormat: Text.PlainText
                  text: String(badge.modelData.label || "")
                  color: badge.modelData.state === "bad" ? root.urgent
                    : (badge.modelData.state === "ok" ? root.foreground : root.dim)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: badge.modelData.state === "bad"
                }
              }

              MouseArea {
                id: badgeMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: badge.actionable ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: if (badge.actionable) root.runDnsTest()
              }

              PanelToolTip {
                visible: badgeMouse.containsMouse && text !== ""
                text: String(badge.modelData.hint || "") + (badge.actionable ? " — click to run" : "")
                fontFamily: root.fontFamily
              }
            }
          }
        }

        PanelSeparator { foreground: root.foreground }

        CursorSurface {
          id: menuRow
          width: parent.width
          implicitHeight: menuText.implicitHeight + Style.spacing.rowPaddingX
          foreground: root.foreground

          Text {
            id: menuText
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.margins: Style.space(12)
            textFormat: Text.PlainText
            text: "Servers, tools and settings"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openMenu()
          }
        }

        Text {
          textFormat: Text.PlainText
          width: parent.width
          text: "t toggle · m menu · d DNS test · r refresh · esc close"
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          horizontalAlignment: Text.AlignHCenter
          wrapMode: Text.WordWrap
        }
      }
    }
  }
}
