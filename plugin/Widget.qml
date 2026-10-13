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
//   --ping-now        Ping next to SERVERS (everything), on a group, a click on a
//                     row's ping, or `p` (group/server scope, queued) — the only
//                     time pings are measured (through xray under happd, so also
//                     under the kill switch); fields.activity shows the progress
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
  // Like the clock's `format`: a template in this widget's shell.json entry,
  // placeholders = vpn_manager.LABEL_FIELDS (filled by --status as
  // panel.fields); `f` in the panel cycles labelFormats and writes it back
  // (not `l`: PanelKeyCatcher turns h/j/k/l into moves before textKey).
  readonly property string labelFormat: String(setting("labelFormat", "{label}"))
  readonly property var labelFormats: [
    "{label}",
    "{subscription}: {server}",
    "{server}",
    "{server} · {ping}",
    "{server} · {activity}",
    "{exit_flag} {exit_ip}",
    "{state}",
    "{server} · ↓ {down} ↑ {up}",
    "{protocol} · {server}",
    "{sub_traffic} · {sub_expire}"
  ]
  readonly property bool vertical: bar ? bar.vertical : false

  property bool connected: false
  property string label: ""
  property string tooltip: "VPN"
  property var panelData: ({})
  property bool refreshPending: false
  property bool busy: false

  // Server list (--servers, loaded when the panel opens and after a connect
  // or disconnect — not on the 3 s tick). One flat row model: group headers,
  // an "Auto — best ping" row per open group, servers.
  property var serverGroups: []
  property var expandedGroups: ({})
  property string serverFilter: ""
  property int serverCursor: -1
  property string pendingKey: ""
  // rows whose ping was just asked for: "…" until the backend has queued it
  // (then the list's own `pinging` carries it) — cleared by the first list
  // load started after pingSettle
  property var pendingPing: ({})
  property bool clearPendingOnLoad: false
  readonly property var serverRows: buildServerRows(serverGroups, expandedGroups, serverFilter)

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

  function rowKey(group, server) {
    return String(group.id) + "\n" + (server ? String(server.name) : "")
  }

  // A group is open when the user opened it, else when it holds the active
  // server; a filter opens every group with a match and hides the rest.
  function buildServerRows(groups, expanded, filter) {
    var q = String(filter || "").trim().toLowerCase()
    var rows = []
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i]
      var servers = g.servers || []
      if (q !== "") servers = servers.filter(function(s) {
        var hay = String(s.name) + " " + String(s.protocol || "") + " " + String(s.country || "")
        return hay.toLowerCase().indexOf(q) !== -1
      })
      if (q !== "" && servers.length === 0) continue
      var open = q !== "" || (expanded[g.id] === undefined ? g.active === true : expanded[g.id] === true)
      rows.push({ kind: "group", group: g, open: open, count: servers.length })
      if (!open) continue
      var best = null
      for (var j = 0; j < servers.length; j++) {
        var s = servers[j]
        if (s.ping_ms === null || s.ping_ms === undefined || s.active) continue
        if (!best || s.ping_ms < best.ping_ms) best = s
      }
      if (best && servers.length > 1) rows.push({ kind: "auto", group: g, server: best })
      for (var k = 0; k < servers.length; k++) rows.push({ kind: "server", group: g, server: servers[k] })
    }
    return rows
  }

  function setGroupOpen(group, open) {
    var next = {}
    for (var key in expandedGroups) next[key] = expandedGroups[key]
    next[group.id] = open
    expandedGroups = next
  }

  function loadServers() {
    if (!serversProc.running) serversProc.running = true
  }

  function runArgs(args) {
    Quickshell.execDetached(["python3", root.backend].concat(args))
  }

  // A group's or a server's ping (click on its ping, its group button, `p`).
  function pingRow(row) {
    if (!row) return
    var g = row.group
    var args = ["--ping-now"]
    var key
    if (row.kind === "group") {
      key = rowKey(g, null)
      args.push("group", String(g.id))
    } else {
      key = rowKey(g, row.server)
      args.push("server", String(g.provider), String(row.server.name), String(g.subscription_id || ""))
    }
    var next = {}
    for (var k in pendingPing) next[k] = pendingPing[k]
    next[key] = true
    pendingPing = next
    runArgs(args)
    pingSettle.restart()
  }

  // A group header: its scope runs/queued. A server: not measured yet in
  // the run that covers it (the backend's per-row `pinging`) — a result
  // already in shows while the rest of the group is measured.
  function rowPinging(row) {
    if (!row) return false
    var g = row.group
    if (pendingPing[rowKey(g, null)] === true) return true
    if (row.kind === "group") return g.pinging === true
    return row.server.pinging === true || pendingPing[rowKey(g, row.server)] === true
  }

  function activateServerRow(row) {
    if (!row) return
    if (row.kind === "group") { setGroupOpen(row.group, !row.open); return }
    var g = row.group, s = row.server
    pendingKey = rowKey(g, s)
    if (row.kind === "server" && s.active) {
      runArgs(["--disconnect", g.provider, s.name])
      return
    }
    var args = ["--connect", g.provider, s.name]
    if (g.subscription_id) args.push(g.subscription_id)
    runArgs(args)
  }

  function moveServerCursor(dy) {
    pointerGate.reset()
    if (serverRows.length === 0) return
    serverCursor = Math.max(0, Math.min(serverRows.length - 1, serverCursor + dy))
    scrollRowIntoView(serverCursor)
  }

  // h/l on a group header: collapse/expand, like a file tree
  function openCursorGroup(open) {
    var row = serverRows[serverCursor]
    if (row && row.kind === "group") setGroupOpen(row.group, open)
  }

  function scrollRowIntoView(index) {
    if (!panelFlick || index < 0 || index >= serverColumn.children.length) return
    Qt.callLater(function() {
      var item = serverColumn.children[index]
      if (!item) return
      var top = item.mapToItem(panelFlick.contentItem, 0, 0).y
      var bottom = top + item.height
      var margin = Style.space(6)
      var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
      if (top < panelFlick.contentY + margin) panelFlick.contentY = Math.max(0, top - margin)
      else if (bottom > panelFlick.contentY + panelFlick.height - margin)
        panelFlick.contentY = Math.min(maxY, bottom + margin - panelFlick.height)
    })
  }

  // What the backend is busy with ("ping 23/150"): next to the connection
  // unless the template places {activity} itself, alone when disconnected.
  // Not while the panel is open: the panel is centred under this button, so
  // a label growing mid-ping slid it sideways — and the panel shows the
  // progress itself ("…" on the rows).
  readonly property string activity: root.opened ? ""
    : String((panelData.fields || {}).activity || "")
  readonly property string barLabel: {
    if (!connected) return activity
    var text = formatLabel(labelFormat)
    if (activity !== "" && labelFormat.indexOf("{activity}") === -1)
      text = text !== "" ? text + " · " + activity : activity
    return text
  }

  // "{subscription}: {server}" -> "ARTEMIDA: 🇩🇪 Germany 1". An empty
  // placeholder takes one separator with it: the one before it when a value
  // precedes it ("{server} · {ping}" -> "server"), else the one after
  // ("{subscription}: {server}" -> "server" for WireGuard). A bracket pair
  // around it goes together ("{server} ({ping})" -> "server"). An unknown
  // placeholder stays as typed, so a typo shows.
  function formatLabel(fmt) {
    var values = panelData.fields || {}
    var closers = { "(": ")", "[": "]", "«": "»" }
    // even indexes: literal text, odd: {placeholder}
    var parts = String(fmt).split(/(\{[a-z0-9_]+\})/)
    var shown = []
    for (var i = 1; i < parts.length; i += 2) {
      var key = parts[i].slice(1, -1)
      shown[i] = values[key] === undefined ? parts[i] : String(values[key] || "")
    }
    for (var j = 1; j < parts.length; j += 2) {
      if (shown[j] !== "") continue
      var before = parts[j - 1]
      var after = parts[j + 1]
      var close = closers[before.slice(-1)]
      if (close && after.charAt(0) === close) {
        parts[j - 1] = before.slice(0, -1).replace(/\s+$/, "")
        parts[j + 1] = after.slice(1)
        continue
      }
      var valueBefore = false
      for (var k = j - 2; k > 0; k -= 2) if (shown[k] !== "") { valueBefore = true; break }
      if (valueBefore) parts[j - 1] = ""
      else parts[j + 1] = ""
    }
    var out = ""
    for (var n = 0; n < parts.length; n++) out += n % 2 === 1 ? shown[n] : parts[n]
    out = out.trim()
    return out !== "" ? out : label
  }

  function cycleLabelFormat() {
    var i = labelFormats.indexOf(labelFormat)
    var entry = { id: root.moduleName }
    for (var key in root.settings) if (key !== "id") entry[key] = root.settings[key]
    entry.labelFormat = labelFormats[(i + 1) % labelFormats.length]
    // local first so the label changes on the key press; the shell.json
    // write comes back through the bar as the same value (as the clock does)
    root.settings = entry
    if (root.bar && root.bar.shell && typeof root.bar.shell.updateEntryInline === "function")
      root.bar.shell.updateEntryInline(root.moduleName, entry)
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
    loadServers()
    serverCursor = -1
    serverFilter = ""
    if (panelFlick) panelFlick.contentY = 0
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }
  onServerRowsChanged: {
    pointerGate.reset()  // rows just moved under a still pointer — not a hover
    if (serverCursor >= serverRows.length) serverCursor = serverRows.length - 1
  }

  // Hover moves the cursor only when the pointer itself moved: a rebuilt or
  // scrolled list slides rows under a still pointer, and each one used to
  // grab the cursor (the filter jumped it to row 27). Measured against the
  // viewport, so scrolling isn't movement.
  PointerMoveGate {
    id: pointerGate
    referenceItem: panelFlick
  }

  IpcHandler {
    target: root.ipcTarget

    // the backend calls this after every connect/disconnect
    function refresh(): void {
      root.refresh()
      if (root.opened) root.loadServers()
    }
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

  Process {
    id: serversProc
    command: ["python3", root.backend, "--servers"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var data = null
        try { data = JSON.parse(String(text || "")) } catch (e) {}
        root.serverGroups = data && data.groups instanceof Array ? data.groups : []
        if (root.clearPendingOnLoad) {
          root.pendingPing = ({})
          root.clearPendingOnLoad = false
        }
        root.pendingKey = ""
      }
    }
  }

  // The backend queues a ping within a moment of the click; after that the
  // server list's `pinging` shows the "…" and pendingPing can go.
  Timer {
    id: pingSettle
    interval: 1500
    onTriggered: {
      if (serversProc.running) { restart(); return }
      root.clearPendingOnLoad = true
      root.loadServers()
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
      + (root.showLabel && root.barLabel !== "" && !root.vertical ? "  " + root.barLabel : "")
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
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(680))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) root.moveServerCursor(dy)
        else root.openCursorGroup(dx > 0)
      }
      onActivateRequested: {
        if (root.serverCursor >= 0) root.activateServerRow(root.serverRows[root.serverCursor])
        else root.openMenu()
      }
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        var k = String(t).toLowerCase()
        if (k === "t") root.togglePower()
        else if (k === "m") root.openMenu()
        else if (k === "d") root.runDnsTest()
        else if (k === "r") { root.refresh(); root.loadServers() }
        else if (k === "f") root.cycleLabelFormat()
        else if (k === "p" && root.serverCursor >= 0) root.pingRow(root.serverRows[root.serverCursor])
        else if (k === "/") filterField.forceActiveFocus()
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

      Column {
        id: column
        width: panelFlick.width
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

        Item {
          width: parent.width
          implicitHeight: Math.max(serversHeader.implicitHeight, pingButton.implicitHeight)

          PanelSectionHeader {
            id: serversHeader
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: "SERVERS"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Text {
            id: pingButton
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            textFormat: Text.PlainText
            text: "\uf021 Ping"  // nf-fa-refresh
            color: pingMouse.containsMouse ? root.foreground : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          MouseArea {
            id: pingMouse
            anchors.fill: pingButton
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.run("--ping-now")
          }

          PanelToolTip {
            visible: pingMouse.containsMouse
            text: root.activity !== "" ? "Measuring: " + root.activity
                                       : "Measure every server's delay through xray"
            fontFamily: root.fontFamily
          }
        }

        TextField {
          id: filterField
          width: parent.width
          foreground: root.foreground
          placeholderText: "Filter servers — press /"
          text: root.serverFilter
          onTextChanged: {
            root.serverFilter = text
            root.serverCursor = text !== "" ? 0 : -1
          }
          onAccepted: {
            root.activateServerRow(root.serverRows[Math.max(0, root.serverCursor)])
          }
          Keys.onPressed: function(event) {
            if (event.key === Qt.Key_Down) { root.moveServerCursor(1); event.accepted = true }
            else if (event.key === Qt.Key_Up) { root.moveServerCursor(-1); event.accepted = true }
            else if (event.key === Qt.Key_Escape) {
              if (text !== "") text = ""
              keyCatcher.forceActiveFocus()
              event.accepted = true
            }
          }
        }

        Text {
          visible: root.serverRows.length === 0
          width: parent.width
          textFormat: Text.PlainText
          text: root.serverFilter !== "" ? "No servers match." : (serversProc.running ? "Loading servers…" : "No servers.")
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          horizontalAlignment: Text.AlignHCenter
        }

        Column {
          id: serverColumn
          width: parent.width
          spacing: Style.space(2)

          Repeater {
            model: root.serverRows
            ServerRow {
              required property var modelData
              required property int index
              width: serverColumn.width
              row: modelData
              rowIndex: index
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
          // ⚙ Settings → "Show key hints in the panel" (config panel_key_hints)
          visible: root.panelData.key_hints !== false
          textFormat: Text.PlainText
          width: parent.width
          text: "j/k move · enter connect · p ping · / filter · t toggle · m menu · d DNS · f label · r refresh"
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

  component ServerRow: CursorSurface {
    id: serverRow
    property var row: null
    property int rowIndex: 0
    readonly property bool isGroup: row && row.kind === "group"
    readonly property bool isAuto: row && row.kind === "auto"
    readonly property var server: row && row.server ? row.server : null
    readonly property bool isActive: row && row.kind === "server" && server && server.active === true
    readonly property bool pending: row && !isGroup && root.pendingKey === root.rowKey(row.group, server)
    readonly property string leftText: {
      if (!row) return ""
      if (isGroup) return row.group.title
      if (isAuto) return "Auto — best ping · " + server.name
      return server.name
    }
    readonly property bool pinging: root.rowPinging(row)
    readonly property string rightText: {
      if (!row) return ""
      if (pending || pinging) return "…"
      if (isGroup) return row.group.summary || (row.count + " servers")
      return String(server.ping || "")
    }

    hasCursor: root.serverCursor === rowIndex
    current: isActive
    foreground: root.foreground
    implicitHeight: rowInner.implicitHeight + (isGroup ? Style.spacing.lg : Style.spacing.md)

    MouseArea {
      id: rowMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onPositionChanged: function(mouse) {
        if (pointerGate.moved(rowMouse, mouse)) root.serverCursor = serverRow.rowIndex
      }
      onClicked: root.activateServerRow(serverRow.row)
    }

    Row {
      id: rowInner
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(6)
      anchors.rightMargin: Style.space(8)
      spacing: Style.space(8)

      Text {
        id: rowGlyph
        // nf-fa-caret_down / caret_right / bolt / circle
        text: serverRow.isGroup ? (serverRow.row.open ? "\uf0d7" : "\uf0da")
          : (serverRow.isAuto ? "\uf0e7" : (serverRow.isActive ? "\uf111" : ""))
        color: serverRow.isActive || serverRow.isGroup ? root.foreground : root.dim
        font.family: root.fontFamily
        font.pixelSize: serverRow.isActive ? Style.font.caption : Style.font.body
        width: Style.space(16)
        horizontalAlignment: Text.AlignHCenter
        anchors.verticalCenter: parent.verticalCenter
      }

      Text {
        textFormat: Text.PlainText
        text: serverRow.leftText
        color: serverRow.isAuto ? root.dim : root.foreground
        font.family: root.fontFamily
        font.pixelSize: serverRow.isGroup ? Style.font.body : Style.font.bodySmall
        font.bold: serverRow.isGroup || serverRow.isActive
        elide: Text.ElideRight
        width: parent.width - rowGlyph.width - rightLabel.width - groupPing.width
          - parent.spacing * (groupPing.visible ? 3 : 2)
        anchors.verticalCenter: parent.verticalCenter
      }

      Text {
        id: rightLabel
        textFormat: Text.PlainText
        // never measured: a ping glyph on hover, so there is still something to click
        text: serverRow.rightText !== "" || serverRow.isGroup ? serverRow.rightText
          : (rowMouse.containsMouse ? "\uf021" : "")  // nf-fa-refresh
        color: pingMouse.containsMouse && !serverRow.isGroup ? root.foreground
          : (serverRow.server && (serverRow.server.stale || serverRow.server.ping_ms === null)
            ? root.dim : (serverRow.isGroup ? root.dim : root.foreground))
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        anchors.verticalCenter: parent.verticalCenter

        // a server's ping is its own button: click = measure it (the rest
        // of the row connects)
        MouseArea {
          id: pingMouse
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          enabled: !serverRow.isGroup && !serverRow.pending
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: root.pingRow(serverRow.row)
        }
      }

      // a group's ping button, next to its summary
      Text {
        id: groupPing
        visible: serverRow.isGroup
        textFormat: Text.PlainText
        text: "\uf021"  // nf-fa-refresh
        color: groupPingMouse.containsMouse ? root.foreground : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        anchors.verticalCenter: parent.verticalCenter

        MouseArea {
          id: groupPingMouse
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          enabled: serverRow.isGroup
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: root.pingRow(serverRow.row)
        }
      }
    }

    PanelToolTip {
      visible: pingMouse.containsMouse || groupPingMouse.containsMouse
      text: serverRow.pinging ? "Measuring…"
        : (serverRow.isGroup ? "Ping every server of " + serverRow.row.group.title : "Click to ping")
      fontFamily: root.fontFamily
    }

    PanelToolTip {
      visible: rowMouse.containsMouse && !pingMouse.containsMouse && !serverRow.isGroup
        && serverRow.server !== null
      text: serverRow.server
        ? (serverRow.isActive ? "Disconnect" : "Connect") + (serverRow.server.protocol ? " · " + serverRow.server.protocol : "")
        : ""
      fontFamily: root.fontFamily
    }
  }
}
