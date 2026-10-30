import QtQuick
import qs.Commons
import qs.Ui

// One row of the server list (protocol / group header / "Auto — best ping" / server),
// shared by the bar panel and the app window. `host` is the Widget (state +
// actions), `gate` the owning list's PointerMoveGate.
CursorSurface {
  id: serverRow
  property var host: null
  property var gate: null
  property var row: null
  property int rowIndex: 0
  // in the app window: "+ Import" on protocols, right click for profiles
  property bool inWindow: false
  readonly property bool canImport: inWindow && isProvider && !!row.provider.importer
  readonly property bool isGroup: row && row.kind === "group"
  // the tree layout's top level: a protocol (Happ, WireGuard, …)
  readonly property bool isProvider: row && row.kind === "provider"
  readonly property bool isHeader: isGroup || isProvider
  readonly property bool isAuto: row && row.kind === "auto"
  readonly property var server: row && row.server ? row.server : null
  readonly property bool isActive: row && row.kind === "server" && server && server.active === true
  readonly property bool pending: row && !isHeader && host.pendingKey === host.rowKey(row.group, server)
  readonly property string leftText: {
    if (!row) return ""
    if (isProvider) return row.provider.name
    if (isGroup) return row.group.title
    if (isAuto) return "Auto — best ping · " + server.name
    if (server && server.orphan) return server.name + " · no profile"
    return server.name
  }
  readonly property bool pinging: host.rowPinging(row)
  readonly property string countText: row ? row.count + (row.count === 1 ? " server" : " servers") : ""
  readonly property string rightText: {
    if (!row) return ""
    if (isProvider) return row.provider.total > 0 ? countText : "empty"
    if (pending || pinging) return "…"
    if (isGroup) return row.group.summary || countText
    return String(server.ping || "")
  }

  hasCursor: host.serverCursor === rowIndex
  current: isActive
  foreground: host.foreground
  implicitHeight: rowInner.implicitHeight + (isHeader ? Style.spacing.lg : Style.spacing.md)

  MouseArea {
    id: rowMouse
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    acceptedButtons: Qt.LeftButton | Qt.RightButton
    onPositionChanged: function(mouse) {
      if (serverRow.gate.moved(rowMouse, mouse)) {
        serverRow.host.keyboardCursor = false
        serverRow.host.serverCursor = serverRow.rowIndex
      }
    }
    onClicked: function(mouse) {
      if (mouse.button === Qt.RightButton) {
        if (serverRow.inWindow) serverRow.host.showProfile(serverRow.row)
        return
      }
      serverRow.host.activateServerRow(serverRow.row)
    }
  }

  Row {
    id: rowInner
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.verticalCenter: parent.verticalCenter
    anchors.leftMargin: Style.space(6) + (serverRow.row ? serverRow.row.depth || 0 : 0) * Style.space(16)
    anchors.rightMargin: Style.space(8)
    spacing: Style.space(8)

    Text {
      id: rowGlyph
      // nf-fa-caret_down / caret_right / bolt / circle
      text: serverRow.isHeader ? (serverRow.row.open ? "" : "")
        : (serverRow.isAuto ? "" : (serverRow.isActive ? "" : ""))
      color: serverRow.isActive || serverRow.isHeader ? serverRow.host.foreground : serverRow.host.dim
      font.family: serverRow.host.fontFamily
      font.pixelSize: serverRow.isActive ? Style.font.caption : Style.font.body
      width: Style.space(16)
      horizontalAlignment: Text.AlignHCenter
      anchors.verticalCenter: parent.verticalCenter
    }

    Text {
      textFormat: Text.PlainText
      text: serverRow.leftText
      color: serverRow.isAuto ? serverRow.host.dim : serverRow.host.foreground
      font.family: serverRow.host.fontFamily
      font.pixelSize: serverRow.isHeader ? Style.font.body : Style.font.bodySmall
      font.bold: serverRow.isHeader || serverRow.isActive
      elide: Text.ElideRight
      width: parent.width - rowGlyph.width - rightLabel.width
        - (groupPing.visible ? groupPing.width + parent.spacing : 0)
        - (importButton.visible ? importButton.width + parent.spacing : 0)
        - (starButton.visible ? starButton.width + parent.spacing : 0)
        - parent.spacing * 2
      anchors.verticalCenter: parent.verticalCenter
    }

    Text {
      id: rightLabel
      textFormat: Text.PlainText
      // never measured: a ping glyph on hover, so there is still something to click
      text: serverRow.rightText !== "" || serverRow.isHeader ? serverRow.rightText
        : (rowMouse.containsMouse ? "" : "")  // nf-fa-refresh
      color: pingMouse.containsMouse && !serverRow.isHeader ? serverRow.host.foreground
        : (serverRow.server && (serverRow.server.stale || serverRow.server.ping_ms === null)
          ? serverRow.host.dim : (serverRow.isHeader ? serverRow.host.dim : serverRow.host.foreground))
      font.family: serverRow.host.fontFamily
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter

      // a server's ping is its own button: click = measure it (the rest
      // of the row connects)
      MouseArea {
        id: pingMouse
        anchors.fill: parent
        anchors.margins: -Style.space(4)
        enabled: !serverRow.isHeader && !serverRow.pending
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: serverRow.host.pingRow(serverRow.row)
      }
    }

    // ★ a favourite (always), ☆ on hover: click (or `s`) stars it — QUICK CONNECT
    Text {
      id: starButton
      visible: !!serverRow.server && serverRow.row.kind === "server"
        && (serverRow.server.favourite === true || rowMouse.containsMouse || starMouse.containsMouse)
      textFormat: Text.PlainText
      text: serverRow.server && serverRow.server.favourite ? "\uf005" : "\uf006"  // nf-fa-star / star_o
      color: starMouse.containsMouse || (serverRow.server && serverRow.server.favourite)
        ? serverRow.host.foreground : serverRow.host.dim
      font.family: serverRow.host.fontFamily
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter

      MouseArea {
        id: starMouse
        anchors.fill: parent
        anchors.margins: -Style.space(4)
        enabled: starButton.visible
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: serverRow.host.toggleFavourite(serverRow.row)
      }
    }

    // a protocol's "+ Import" (the window only)
    Text {
      id: importButton
      visible: serverRow.canImport
      textFormat: Text.PlainText
      text: "+ Import"
      color: importMouse.containsMouse ? serverRow.host.foreground : serverRow.host.dim
      font.family: serverRow.host.fontFamily
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter

      MouseArea {
        id: importMouse
        anchors.fill: parent
        anchors.margins: -Style.space(4)
        enabled: serverRow.canImport
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: serverRow.host.startImport(serverRow.row.provider)
      }
    }

    // a group's ping button, next to its summary
    Text {
      id: groupPing
      visible: serverRow.isGroup
      textFormat: Text.PlainText
      text: ""  // nf-fa-refresh
      color: groupPingMouse.containsMouse ? serverRow.host.foreground : serverRow.host.dim
      font.family: serverRow.host.fontFamily
      font.pixelSize: Style.font.caption
      anchors.verticalCenter: parent.verticalCenter

      MouseArea {
        id: groupPingMouse
        anchors.fill: parent
        anchors.margins: -Style.space(4)
        enabled: serverRow.isGroup
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: serverRow.host.pingRow(serverRow.row)
      }
    }
  }

  PanelToolTip {
    visible: pingMouse.containsMouse || groupPingMouse.containsMouse
    text: serverRow.pinging ? "Measuring…"
      : (serverRow.isGroup ? "Ping every server of " + serverRow.row.group.title : "Click to ping")
    fontFamily: serverRow.host.fontFamily
  }

  PanelToolTip {
    visible: rowMouse.containsMouse && !pingMouse.containsMouse && !serverRow.isHeader
      && serverRow.server !== null
    text: serverRow.server
      ? (serverRow.isActive ? "Disconnect" : "Connect") + (serverRow.server.protocol ? " · " + serverRow.server.protocol : "")
      : ""
    fontFamily: serverRow.host.fontFamily
  }
}
