import QtQuick
import qs.Commons
import qs.Ui

// SERVERS header + Ping, the filter field and the rows — the bar panel's and
// the app window's Locations. State and actions stay on `host` (the Widget),
// so both show the same list, cursor and pings; `flick` is the Flickable this
// column scrolls in.
Column {
  id: list
  property var host: null
  property Flickable flick: null
  readonly property alias filterField: filterField
  readonly property bool filterFocused: filterField.activeFocus
  // where Esc in the filter hands the keyboard back to
  property Item keyTarget: null
  // the app window's list: "+ Import" and right-click profiles
  property bool inWindow: false
  // tabs/sidebar with one protocol picked: its "+ Import" sits by Ping
  readonly property var pickedProvider: inWindow && host.rowsLayout !== "tree" && host.providerFilter !== ""
    ? host.providerInfo(host.providerFilter) : null
  readonly property bool showHappRefresh: list.host.providerFilter === "Happ"

  spacing: Style.space(12)

  function resetPointer() { pointerGate.reset() }

  function scrollToRow(index) {
    if (!flick || index < 0 || index >= serverColumn.children.length) return
    Qt.callLater(function() {
      var item = serverColumn.children[index]
      if (!item) return
      var top = item.mapToItem(flick.contentItem, 0, 0).y
      var bottom = top + item.height
      var margin = Style.space(6)
      var maxY = Math.max(0, flick.contentHeight - flick.height)
      if (top < flick.contentY + margin) flick.contentY = Math.max(0, top - margin)
      else if (bottom > flick.contentY + flick.height - margin)
        flick.contentY = Math.min(maxY, bottom + margin - flick.height)
    })
  }

  // Hover moves the cursor only when the pointer itself moved: a rebuilt or
  // scrolled list slides rows under a still pointer, and each one used to
  // grab the cursor (the filter jumped it to row 27). Measured against the
  // viewport, so scrolling isn't movement.
  PointerMoveGate {
    id: pointerGate
    referenceItem: list.flick
  }

  QuickConnect {
    width: parent.width
    host: list.host
  }

  Item {
    width: parent.width
    implicitHeight: Math.max(serversHeader.implicitHeight, pingButton.implicitHeight)

    PanelSectionHeader {
      id: serversHeader
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      text: "SERVERS"
      foreground: list.host.foreground
      fontFamily: list.host.fontFamily
    }

    HappSubRefresh {
      id: happRefreshButton
      visible: list.showHappRefresh
      host: list.host
      anchors.right: pingButton.left
      anchors.rightMargin: Style.space(12)
      anchors.verticalCenter: parent.verticalCenter
    }

    Text {
      id: headerImport
      visible: !!list.pickedProvider && !!list.pickedProvider.importer
      anchors.right: (happRefreshButton.visible ? happRefreshButton.left : pingButton.left)
      anchors.rightMargin: Style.space(12)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      text: "+ Import"
      color: headerImportMouse.containsMouse ? list.host.foreground : list.host.dim
      font.family: list.host.fontFamily
      font.pixelSize: Style.font.caption

      MouseArea {
        id: headerImportMouse
        anchors.fill: parent
        enabled: headerImport.visible
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: list.host.startImport(list.pickedProvider)
      }
    }

    Text {
      id: pingButton
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      text: ""  // nf-fa-refresh
      color: pingMouse.containsMouse ? list.host.foreground : list.host.dim
      font.family: list.host.fontFamily
      font.pixelSize: Style.font.caption
    }

    MouseArea {
      id: pingMouse
      anchors.fill: pingButton
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: list.host.run("--ping-now")
    }

    PanelToolTip {
      visible: pingMouse.containsMouse
      text: list.host.pingActivity !== "" ? "Measuring: " + list.host.pingActivity
                                          : "Measure every server's delay through xray"
      fontFamily: list.host.fontFamily
    }
  }

  TextField {
    id: filterField
    width: parent.width
    foreground: list.host.foreground
    placeholderText: "Filter servers — press /"
    text: list.host.serverFilter
    onTextChanged: {
      list.host.serverFilter = text
      list.host.keyboardCursor = text !== ""
      list.host.serverCursor = text !== "" ? 0 : -1
    }
    onAccepted: {
      list.host.activateServerRow(list.host.serverRows[Math.max(0, list.host.serverCursor)])
    }
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Down) { list.host.moveServerCursor(1); event.accepted = true }
      else if (event.key === Qt.Key_Up) { list.host.moveServerCursor(-1); event.accepted = true }
      else if (event.key === Qt.Key_Escape) {
        if (text !== "") text = ""
        if (list.keyTarget) list.keyTarget.forceActiveFocus()
        event.accepted = true
      }
    }
  }

  Text {
    visible: list.host.serverRows.length === 0
    width: parent.width
    textFormat: Text.PlainText
    text: list.host.serverFilter !== "" ? "No servers match."
      : (list.host.serversLoading ? "Loading servers…" : "No servers.")
    color: list.host.dim
    font.family: list.host.fontFamily
    font.pixelSize: Style.font.bodySmall
    horizontalAlignment: Text.AlignHCenter
  }

  Column {
    id: serverColumn
    width: parent.width
    spacing: Style.space(2)

    Repeater {
      model: list.host.serverRows
      ServerRow {
        required property var modelData
        required property int index
        width: serverColumn.width
        host: list.host
        gate: pointerGate
        inWindow: list.inWindow
        row: modelData
        rowIndex: index
      }
    }
  }
}
