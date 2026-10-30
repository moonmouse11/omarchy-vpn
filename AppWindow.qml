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


  title: "VPN"
  color: Color.background
  implicitWidth: 960
  implicitHeight: 640
  minimumSize: Qt.size(720, 480)
  visible: false  // Widget.openWindow() shows it; Esc or Hyprland's close hides it

  onVisibleChanged: {
    if (visible) Qt.callLater(function() {
      if (win.host.checkOpen) checkCard.focusKeys()
      else keyCatcher.forceActiveFocus()
    })
    else if (host) host.closeProfileBar()
  }

  // the Profiles strip takes the keyboard while it asks for something
  Connections {
    target: win.host
    function onProfileModeChanged() {
      if (win.host.profileMode === "import") profileBar.focusInput()
      else if (win.host.profileMode === "") keyCatcher.forceActiveFocus()
    }
    function onCheckOpenChanged() {
      if (win.host.checkOpen) checkCard.focusKeys()
      else keyCatcher.forceActiveFocus()
    }
    function onDeleteConfirmOpenChanged() {
      if (win.host.deleteConfirmOpen) confirmKeys.forceActiveFocus()
      else if (win.host.profileMode !== "") keyCatcher.forceActiveFocus()
    }
  }

  // `i`: the cursor's protocol (its own row, or the one of the server/group
  // under it), else the tabs/sidebar pick
  function importTarget() {
    var row = cursorRow()
    if (!row) return locations.pickedProvider
    return row.kind === "provider" ? row.provider : host.providerInfo(row.group.provider)
  }

  function cursorRow() {
    return host.serverCursor >= 0 ? host.serverRows[host.serverCursor] : null
  }

  PanelKeyCatcher {
    id: keyCatcher
    anchors.fill: parent
    anchors.margins: Style.space(20)
    // typing in the filter must not drive the cursor (j/k/h/l are moves)
    blocked: locations.filterFocused || profileBar.inputFocused || win.host.deleteConfirmOpen
      || win.host.checkOpen
    onMoveRequested: function(dx, dy) {
      if (dy !== 0) win.host.moveServerCursor(dy)
      else win.host.openCursorGroup(dx > 0)
    }
    onActivateRequested: {
      // the profile strip is open: Enter must not connect the row behind it
      if (win.host.profileMode !== "") return
      if (win.host.serverCursor >= 0) win.host.activateServerRow(win.host.serverRows[win.host.serverCursor])
      else win.host.moveServerCursor(1)
    }
    onCloseRequested: {
      if (win.host.profileMode !== "") win.host.closeProfileBar()
      else win.visible = false
    }
    onTextKey: function(t) {
      var k = String(t).toLowerCase()
      if (k === "t") win.host.togglePower()
      else if (k === "d") win.host.runDnsTest()
      else if (k === "r") {
        win.host.refreshHappSubscriptions()
        win.host.refresh()
        win.host.loadServers()
      }
      else if (k === "p" && win.host.serverCursor >= 0) win.host.pingRow(win.host.serverRows[win.host.serverCursor])
      else if (k === "/") locations.filterField.forceActiveFocus()
      else if (k === "s") win.host.toggleFavourite(win.cursorRow())
      else if (k === "i") win.host.startImport(win.importTarget())
      else if (k === "a" && win.host.showProfile(win.cursorRow()) && !win.cursorRow().server.active)
        win.host.profileAction("autostart")
      else if (k === "x" && win.host.showProfile(win.cursorRow()) && !win.cursorRow().server.active)
        win.host.deleteConfirmOpen = true
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

        ProfileBar {
          id: profileBar
          host: win.host
          anchors.top: tabs.bottom
          anchors.topMargin: tabs.visible ? Style.space(12) : 0
          anchors.left: sidebar.right
          anchors.leftMargin: sidebar.visible ? Style.space(16) : 0
          anchors.right: parent.right
        }

        Flickable {
          id: locationsFlick
          anchors.top: profileBar.bottom
          anchors.topMargin: tabs.visible || profileBar.visible ? Style.space(12) : 0
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
            inWindow: true
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

          ToolButtons {
            width: parent.width
            host: win.host
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
      text: "j/k move · h/l fold · enter connect · p ping · s star · / filter · i import · right click profile · a autostart · x delete"
        + (win.host.windowLayout !== "tree" ? " · [ ] protocol" : "")
        + " · t toggle · d DNS · r refresh subs · esc close"
      color: win.host.dim
      font.family: win.host.fontFamily
      font.pixelSize: Style.font.caption
      horizontalAlignment: Text.AlignHCenter
    }
  }

  CheckCard {
    id: checkCard
    anchors.fill: parent
    host: win.host
  }

  // x / Delete…: a profile is gone for good (its config file or NM connection)
  Item {
    id: confirmKeys
    anchors.fill: parent
    visible: win.host.deleteConfirmOpen
    Keys.onPressed: function(event) { if (deleteConfirm.handleKey(event)) event.accepted = true }

    ConfirmDialog {
      id: deleteConfirm
      anchors.fill: parent
      opened: win.host.deleteConfirmOpen
      message: win.host.profileTarget && win.host.profileTarget.server
        ? "Delete " + win.host.profileTarget.server.name + " (" + win.host.profileTarget.group.provider + ")?"
        : ""
      confirmText: "Delete"
      foreground: win.host.foreground
      fontFamily: win.host.fontFamily
      onConfirmed: win.host.profileAction("delete")
      onCanceled: win.host.deleteConfirmOpen = false
    }
  }
}
