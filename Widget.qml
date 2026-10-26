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
//   --tool KEY        the app window's Tools buttons (AppWindow.qml)
//   --disconnect-all  the hero switch, when on
//   --check KIND      DNS leak test / IP info / speed test: the window's check card
//                     (CheckCard.qml), JSON lines read by checkProc
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
  // `omarchy plugin add` only clones: install.sh (sudo) still has to run, and
  // again after `omarchy plugin update` — "missing" / "outdated" / "" (set up)
  property string setupState: ""
  readonly property string pluginDir: decodeURIComponent(
    String(Qt.resolvedUrl(".")).replace(/^file:\/\//, "").replace(/\/$/, ""))
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
  // the app window (AppWindow.qml): SUPER+Shift+V, right click, `m`
  // the real window, not `visible`: Hyprland's close (SUPER+W) leaves `visible` true
  readonly property bool windowOpen: appWindow.backingWindowVisible

  // Server list (--servers, loaded when the panel opens and after a connect
  // or disconnect — not on the 3 s tick). One flat row model: group headers,
  // an "Auto — best ping" row per open group, servers.
  property var serverGroups: []
  // every visible protocol {name, total, active}, empty ones too
  property var serverProviders: []
  // QUICK CONNECT (--servers' `quick`): favourites, recent, the switch's last server
  property var quick: ({ favourites: [], recent: [], last: null })
  // ⚙ Settings → "Protocols in the VPN window": tree | tabs | sidebar.
  // The bar panel is too narrow for a sidebar: always the tree.
  property string windowLayout: "tree"
  // the open panel wins: it shares the rows, and a tabs/sidebar list has no
  // picker there (the window shows the tree meanwhile)
  readonly property string rowsLayout: windowOpen && !opened ? windowLayout : "tree"
  // tabs/sidebar: the picked protocol, "" = All
  property string providerFilter: ""
  readonly property var providerChoices: [{ name: "", total: 0, active: false }].concat(serverProviders)
  property var expandedGroups: ({})
  // the window's Profiles strip (ProfileBar.qml): "" | "import" (target: a
  // protocol of serverProviders) | "profile" (target: a server row)
  property string profileMode: ""
  property var profileTarget: null
  property bool deleteConfirmOpen: false
  // the window's check card (CheckCard.qml); kept here, so a check outlives a
  // closed window. phase: choose (speed) | running | done | error
  property bool checkOpen: false
  property string checkKind: ""
  property string checkTarget: ""
  property string checkPhase: ""
  property var checkChoices: []
  property var checkProgress: null
  property var checkResult: null
  property string checkError: ""
  property double checkAt: 0
  // another check was asked for while one runs: say it didn't start
  property string checkNotice: ""
  property string serverFilter: ""
  property int serverCursor: -1
  // the cursor was put there by the keyboard (j/k, the filter), not by a
  // passing pointer — only then may the power switch connect it
  property bool keyboardCursor: false
  property string pendingKey: ""
  // rows whose ping was just asked for: "…" until the backend has queued it
  // (then the list's own `pinging` carries it) — cleared by the first list
  // load started after pingSettle
  property var pendingPing: ({})
  property bool clearPendingOnLoad: false
  readonly property var serverRows: buildServerRows(serverGroups, serverProviders, expandedGroups,
    serverFilter, rowsLayout, providerFilter)
  readonly property bool serversLoading: serversProc.running
  // the list the keyboard cursor scrolls: the window's while it is open
  readonly property var activeList: windowOpen && !opened ? appWindow.locations : panelList

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

  function matchingServers(g, q) {
    var servers = g.servers || []
    if (q === "") return servers
    return servers.filter(function(s) {
      var hay = String(s.name) + " " + String(s.protocol || "") + " " + String(s.country || "")
      return hay.toLowerCase().indexOf(q) !== -1
    })
  }

  // A header is open when the user opened it, else when it holds the active
  // server; a filter opens every one with a match and hides the rest.
  function isOpen(expanded, key, active, q) {
    return q !== "" || (expanded[key] === undefined ? active === true : expanded[key] === true)
  }

  // One group's rows: its header (unless the protocol row stands for it),
  // an "Auto — best ping" row when open, its servers. `depth` indents.
  function pushGroup(rows, g, servers, open, depth, header) {
    if (header) rows.push({ kind: "group", group: g, open: open, count: servers.length, depth: depth })
    if (!open) return
    var inner = header ? depth + 1 : depth
    var best = null
    for (var j = 0; j < servers.length; j++) {
      var s = servers[j]
      if (s.ping_ms === null || s.ping_ms === undefined || s.active) continue
      if (!best || s.ping_ms < best.ping_ms) best = s
    }
    if (best && servers.length > 1) rows.push({ kind: "auto", group: g, server: best, depth: inner })
    for (var k = 0; k < servers.length; k++)
      rows.push({ kind: "server", group: g, server: servers[k], depth: inner })
  }

  // tree: protocol → (Happ: subscription →) server; tabs/sidebar: the
  // groups of the picked protocol (all for "All"), flat.
  function buildServerRows(groups, providers, expanded, filter, layout, picked) {
    var q = String(filter || "").trim().toLowerCase()
    var rows = []
    if (layout !== "tree") {
      for (var i = 0; i < groups.length; i++) {
        var g = groups[i]
        if (picked !== "" && g.provider !== picked) continue
        var servers = matchingServers(g, q)
        if (q !== "" && servers.length === 0) continue
        pushGroup(rows, g, servers, isOpen(expanded, g.id, g.active, q), 0, true)
      }
      return rows
    }
    for (var p = 0; p < providers.length; p++) {
      var prov = providers[p]
      var mine = [], count = 0
      for (var m = 0; m < groups.length; m++) {
        if (groups[m].provider !== prov.name) continue
        var found = matchingServers(groups[m], q)
        if (q !== "" && found.length === 0) continue
        mine.push({ group: groups[m], servers: found })
        count += found.length
      }
      if (q !== "" && mine.length === 0) continue
      var key = "provider:" + prov.name
      // a protocol with only notice groups (rejected subscriptions, no headers) opens too
      var open = mine.length > 0 && isOpen(expanded, key, prov.active, q)
      rows.push({ kind: "provider", provider: prov, key: key, open: open, count: count, depth: 0 })
      if (!open) continue
      // a subscription is a level of its own; WireGuard's one group is the protocol itself
      var nested = prov.name === "Happ"
      for (var n = 0; n < mine.length; n++) {
        var mg = mine[n].group
        pushGroup(rows, mg, mine[n].servers,
          !nested || isOpen(expanded, mg.id, mg.active, q), 1, nested)
      }
    }
    return rows
  }

  function setExpanded(key, open) {
    var next = {}
    for (var k in expandedGroups) next[k] = expandedGroups[k]
    next[key] = open
    expandedGroups = next
  }

  function rowOpenKey(row) {
    return row.kind === "provider" ? row.key : row.group.id
  }

  function providerInfo(name) {
    for (var i = 0; i < serverProviders.length; i++)
      if (serverProviders[i].name === name) return serverProviders[i]
    return null
  }

  // "+ Import" on a protocol (the window only)
  function startImport(prov) {
    if (!prov || !prov.importer) return
    profileTarget = prov
    profileMode = "import"
  }

  // right click / a / x on a server whose protocol manages profiles
  function showProfile(row) {
    if (!row || row.kind !== "server") return false
    var info = providerInfo(row.group.provider)
    if (!info || !info.manage) return false
    profileTarget = row
    profileMode = "profile"
    return true
  }

  function closeProfileBar() {
    deleteConfirmOpen = false
    profileMode = ""
    profileTarget = null
  }

  // "" = the desktop file chooser (the backend runs it)
  function importFile(path) {
    var args = ["--import", String(profileTarget.name)]
    if (path !== "") args.push(path)
    runArgs(args)
    closeProfileBar()
  }

  // over stdin, never argv: a key is a password (the network panel does the same)
  function importKey(key) {
    importProc.secret = String(key)
    importProc.stdinEnabled = true
    importProc.command = ["python3", root.backend, "--import", String(profileTarget.name), "-"]
    importProc.running = true
    closeProfileBar()
  }

  function profileAction(action) {
    var row = profileTarget
    runArgs(["--profile", action, String(row.group.provider), String(row.server.name)])
    closeProfileBar()
  }

  // [ / ]: the previous / next protocol of the tabs or sidebar
  function stepProvider(dir) {
    if (rowsLayout === "tree") return
    var names = providerChoices.map(function(c) { return c.name })
    var i = names.indexOf(providerFilter)
    providerFilter = names[(Math.max(0, i) + dir + names.length) % names.length]
    serverCursor = -1
  }

  function loadServers() {
    if (!serversProc.running) serversProc.running = true
  }

  function runArgs(args) {
    Quickshell.execDetached(["python3", root.backend].concat(args))
  }

  // A group's or a server's ping (click on its ping, its group button, `p`).
  function pingRow(row) {
    if (!row || row.kind === "provider") return
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
    if (!row || row.kind === "provider") return false
    var g = row.group
    if (pendingPing[rowKey(g, null)] === true) return true
    if (row.kind === "group") return g.pinging === true
    return row.server.pinging === true || pendingPing[rowKey(g, row.server)] === true
  }

  function activateServerRow(row) {
    if (!row) return
    if (row.kind === "group" || row.kind === "provider") { setExpanded(rowOpenKey(row), !row.open); return }
    var g = row.group, s = row.server
    pendingKey = rowKey(g, s)
    if (row.kind === "server" && s.active) {
      runArgs(["--disconnect", g.provider, s.name])
      return
    }
    connectServer(g.provider, s.name, g.subscription_id)
  }

  // the one place --connect's args are built (rows, chips, the switch)
  function connectServer(provider, name, subId) {
    var args = ["--connect", String(provider), String(name)]
    if (subId) args.push(String(subId))
    runArgs(args)
  }

  function moveServerCursor(dy) {
    activeList.resetPointer()
    if (serverRows.length === 0) return
    keyboardCursor = true
    serverCursor = Math.max(0, Math.min(serverRows.length - 1, serverCursor + dy))
    activeList.scrollToRow(serverCursor)
  }

  // h/l on a protocol or group header: collapse/expand, like a file tree
  function openCursorGroup(open) {
    var row = serverRows[serverCursor]
    if (row && (row.kind === "group" || row.kind === "provider")) setExpanded(rowOpenKey(row), open)
  }

  // What the backend is busy with ("ping 23/150"): next to the connection
  // unless the template places {activity} itself, alone when disconnected.
  // Not while the panel is open: the panel is centred under this button, so
  // a label growing mid-ping slid it sideways — and the panel shows the
  // progress itself ("…" on the rows).
  readonly property string pingActivity: String((panelData.fields || {}).activity || "")
  readonly property string activity: root.opened ? "" : pingActivity
  readonly property string barLabel: {
    if (!connected) return activity
    var text = formatLabel(labelFormat)
    if (activity !== "" && labelFormat.indexOf("{activity}") === -1)
      text = text !== "" ? text + " · " + activity : activity
    return text
  }

  // "{subscription}: {server}" -> "Provider B: 🇩🇪 Germany 1". An empty
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

  // sudo asks in the terminal; install.sh restarts the shell when it's done
  function runSetup() {
    close()
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation",
      Util.shellQuote(root.pluginDir + "/install.sh")])
  }

  function openWindow() {
    close()
    refresh()
    loadServers()
    // Hyprland's close (SUPER+W) leaves `visible` true with no window behind
    // it, so set it false first: that remaps a stale one, and an open one
    // comes back to the front (focus) — never an early return on `visible`
    appWindow.visible = false
    appWindow.visible = true
  }

  // The switch: off disconnects everything; on connects the keyboard-picked
  // server, else QUICK CONNECT's last one, else puts the cursor in the list.
  function togglePower() {
    if (connected) {
      busy = true
      run("--disconnect-all")
    } else if (cursorServerRow()) {
      activateServerRow(cursorServerRow())
    } else if (quick.last) {
      quickConnect(quick.last)  // like Mullvad/Proton: the last server
    } else {
      moveServerCursor(1)
    }
  }

  // a QUICK CONNECT chip (or the switch's last server)
  function quickConnect(chip) {
    connectServer(chip.provider, chip.name, chip.sub_id)
  }

  // the row's star, `s`: (un)star a server for QUICK CONNECT
  function toggleFavourite(row) {
    // not "Auto": that's whichever server pings best right now, not one to keep
    if (!row || row.kind !== "server") return
    var args = ["--favourite", String(row.group.provider), String(row.server.name)]
    if (row.group.subscription_id) args.push(String(row.group.subscription_id))
    runArgs(args)
  }

  // the server row ("Auto" included) the keyboard put the cursor on, else
  // null: on its way to the switch the pointer crosses rows and drags the
  // cursor along — a click must not connect whatever it passed last
  function cursorServerRow() {
    if (!keyboardCursor) return null
    var row = serverRows[serverCursor]
    return row && (row.kind === "server" || row.kind === "auto") ? row : null
  }

  // the DNS badge, `d`: from the panel its own check window, in the app
  // window its card
  function runDnsTest() {
    openCheck("dns", opened)
  }

  // Tools → DNS leak test / IP info / Speed test. A running check just
  // shows its card again: one at a time.
  // standalone: from the bar panel — just the check, in CheckWindow.qml (the
  // whole app window was one window too many); else the app window's card
  function openCheck(kind, standalone) {
    if (standalone) {
      close()
      // Hyprland's close leaves `visible` true (see openWindow()); an open one
      // stays put — remapping it would flicker
      if (!checkWindow.backingWindowVisible) {
        checkWindow.visible = false
        checkWindow.visible = true
      } else {
        // already up, maybe behind other windows: bring it forward, like
        // omarchy-launch-or-focus does
        Quickshell.execDetached(["hyprctl", "dispatch",
          'hl.dsp.focus({ window = "title:^VPN Check$" })'])
      }
    } else {
      checkOpen = true
    }
    if (checkProc.running) {
      var titles = { dns: "DNS Leak Test", ip: "IP Info", speed: "Speed Test" }
      checkNotice = kind !== checkKind
        ? titles[kind] + " didn't start: " + titles[checkKind] + " is still running" : ""
      return
    }
    if (kind === "speed") {
      checkKind = "speed"
      checkTarget = ""
      checkChoices = []
      checkPhase = "choose"
      startCheck(["speed"])
    } else {
      runCheck(kind, "")
    }
  }

  function runCheck(kind, target) {
    if (checkProc.running) return
    checkKind = kind
    checkTarget = target
    checkPhase = "running"
    checkNotice = ""
    checkProgress = null
    checkResult = null
    checkError = ""
    startCheck(target !== "" ? [kind, target] : [kind])
  }

  function startCheck(args) {
    checkProc.command = ["python3", root.backend, "--check"].concat(args)
    checkProc.running = true
  }

  // the check keeps running (its bubble too); the card shows it on reopen
  function closeCheck(standalone) {
    if (standalone) checkWindow.visible = false
    else checkOpen = false
    checkNotice = ""
  }

  function checkLine(line) {
    var o = null
    try { o = JSON.parse(String(line)) } catch (e) { return }
    if (!o) return
    if (o.choices) checkChoices = o.choices
    else if (o.step !== undefined) checkProgress = o
    else if (o.result) { checkResult = o.result; checkAt = Date.now(); checkPhase = "done" }
    else if (o.error) { checkError = String(o.error); checkPhase = "error" }
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
      var missing = root.setupState === "missing"
      tooltip = missing ? "VPN: setup needed" : "VPN: backend not responding\n" + root.backend
      panelData = { title: missing ? "Setup needed" : "Backend not responding",
                    meta: missing ? "" : root.backend, badges: [] }
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

  Component.onCompleted: setupCheck.running = true

  onOpenedChanged: if (opened) {
    if (!setupCheck.running) setupCheck.running = true
    refresh()
    loadServers()
    serverCursor = -1
    serverFilter = ""
    if (panelFlick) panelFlick.contentY = 0
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }
  onServerRowsChanged: {
    // rows just moved under a still pointer — not a hover
    panelList.resetPointer()
    appWindow.locations.resetPointer()
    if (serverCursor >= serverRows.length) serverCursor = serverRows.length - 1
  }

  AppWindow {
    id: appWindow
    host: root
  }

  CheckWindow {
    id: checkWindow
    host: root
  }

  Process {
    id: checkProc
    stdout: SplitParser { onRead: function(data) { root.checkLine(data) } }
    onExited: {
      // killed by a switch before it could say so, or crashed
      if (root.checkPhase === "running") {
        root.checkError = "The check stopped without a result"
        root.checkPhase = "error"
      }
    }
  }

  Process {
    id: importProc
    property string secret: ""
    stdinEnabled: true
    onStarted: {
      write(secret + "\n")
      secret = ""
      stdinEnabled = false  // EOF: the backend reads stdin to the end
    }
  }

  IpcHandler {
    target: root.ipcTarget

    // the backend calls this after every connect/disconnect
    function refresh(): void {
      root.refresh()
      if (root.opened || root.windowOpen) root.loadServers()
    }
    function window(): void { root.openWindow() }
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
  }

  // outdated only for a git checkout (omarchy plugin add); make install copies
  Process {
    id: setupCheck
    command: ["bash", "-c",
      "[ -f \"$1\" ] || { echo missing; exit; }\n"
      + "head=$(git -C \"$2\" rev-parse HEAD 2>/dev/null) || exit 0\n"
      + "[ \"$head\" = \"$(cat \"$3\" 2>/dev/null)\" ] || echo outdated",
      "setup-check", root.backend, root.pluginDir,
      Quickshell.env("HOME") + "/.local/share/omarchy-vpn/installed-commit"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.setupState = String(text || "").trim()
    }
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
        root.serverProviders = data && data.providers instanceof Array ? data.providers : []
        root.quick = data && data.quick ? data.quick : { favourites: [], recent: [], last: null }
        root.windowLayout = data && data.layout ? String(data.layout) : "tree"
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
      else if (buttonCode === Qt.RightButton) root.openWindow()
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
      // typing in the filter must not drive the cursor (j/k/h/l are moves)
      blocked: panelList.filterFocused
      onMoveRequested: function(dx, dy) {
        if (dy !== 0) root.moveServerCursor(dy)
        else root.openCursorGroup(dx > 0)
      }
      onActivateRequested: {
        if (root.serverCursor >= 0) root.activateServerRow(root.serverRows[root.serverCursor])
        else root.moveServerCursor(1)
      }
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        var k = String(t).toLowerCase()
        if (k === "t") root.togglePower()
        else if (k === "m") root.openWindow()
        else if (k === "d") root.runDnsTest()
        else if (k === "r") { root.refresh(); root.loadServers() }
        else if (k === "f") root.cycleLabelFormat()
        else if (k === "p" && root.serverCursor >= 0) root.pingRow(root.serverRows[root.serverCursor])
        else if (k === "s" && root.serverCursor >= 0) root.toggleFavourite(root.serverRows[root.serverCursor])
        else if (k === "/") panelList.filterField.forceActiveFocus()
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

        Column {
          width: parent.width
          spacing: Style.space(8)
          visible: root.setupState !== ""

          Text {
            width: parent.width
            wrapMode: Text.Wrap
            textFormat: Text.PlainText
            text: root.setupState === "missing"
              ? "The VPN backend isn't installed yet. Setup installs it with a small root helper and a sudoers rule for it (your password is asked once in a terminal)."
              : "The plugin was updated: run setup again to update the installed backend and helpers."
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          Button {
            text: root.setupState === "missing" ? "Finish setup" : "Update setup"
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            bordered: true
            onClicked: root.runSetup()
          }
        }

        ConnectionSummary {
          width: parent.width
          host: root
        }

        PanelSeparator { foreground: root.foreground }

        PanelSectionHeader {
          text: "TOOLS"
          foreground: root.foreground
          fontFamily: root.fontFamily
        }

        ToolButtons {
          width: parent.width
          host: root
          standalone: true
        }

        PanelSeparator { foreground: root.foreground }

        ServerList {
          id: panelList
          width: parent.width
          host: root
          flick: panelFlick
          keyTarget: keyCatcher
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
            text: "Open the VPN window"
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openWindow()
          }
        }

        Text {
          // ⚙ Settings → "Show key hints in the panel" (config panel_key_hints)
          visible: root.panelData.key_hints !== false
          textFormat: Text.PlainText
          width: parent.width
          text: "j/k move · enter connect · p ping · s star · / filter · t toggle · m window · d DNS · f label · r refresh"
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
}
