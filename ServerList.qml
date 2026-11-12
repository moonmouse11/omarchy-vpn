import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

// The one scrolling server surface, shared by the bar panel and the app
// window's Locations: a ListView so only visible rows own delegates (a
// hidden surface binds `active: false`, empties the model and owns none).
// The panel's pre-server content scrolls as `preamble` above the rows, its
// menu/key hints as `tail` in the footer — one continuous scroll either way.
// State and actions stay on `host` (the Widget), so both surfaces show the
// same list, cursor and pings.
//
// The header content (preamble, Quick Connect, SERVERS/Ping, filter) is a
// DIRECT CHILD of the view, not the `header:` Component: the view recreates
// its header item on every model rebuild, which destroyed the filter's
// focus mid-keystroke (the rest of the input landed on the key catcher and
// fired actions). A direct child is never recreated; the empty `header:`
// spacer below just reserves its height so delegates start underneath.
ListView {
  id: list
  property var host: null
  // false while the panel/window is hidden: the model is [] and no
  // ServerRow delegates exist
  property bool active: false
  property Component preamble: null
  property Component tail: null
  readonly property alias filterField: filterInput
  readonly property bool filterFocused: filterInput.activeFocus
  // where Esc in the filter hands the keyboard back to
  property Item keyTarget: null
  // the app window's list: "+ Import" and right-click profiles
  property bool inWindow: false
  // tabs/sidebar with one protocol picked: its "+ Import" sits by Ping
  readonly property var pickedProvider: inWindow && host.rowsLayout !== "tree" && host.providerFilter !== ""
    ? host.providerInfo(host.providerFilter) : null

  model: active ? host.serverRows : []
  delegate: ServerRow {
    required property var modelData
    required property int index
    width: list.width
    // ListView (unlike the old Column) doesn't fall back to implicitHeight
    height: implicitHeight
    host: list.host
    gate: pointerGate
    inWindow: list.inWindow
    row: modelData
    rowIndex: index
  }
  spacing: Style.space(2)
  clip: true
  boundsBehavior: Flickable.StopAtBounds
  interactive: contentHeight > height
  ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

  // Typing stays local to the field; Enter applies the filter (the only
  // model rebuild while the field is focused — no more typed characters
  // need it), a second Enter activates the row. Esc clears and hands focus
  // back. reopening resyncs a field whose binding was broken by typing
  onActiveChanged: if (active) Qt.callLater(function() {
    filterInput.text = list.host.serverFilter
  })

  // Editing breaks the initial text binding; mirror only committed changes
  // so simultaneously visible fields follow the shared applied filter.
  Connections {
    target: list.host
    function onServerFilterChanged() { filterInput.text = list.host.serverFilter }
  }

  function resetPointer() { pointerGate.reset() }

  function focusFilter() { filterInput.forceActiveFocus() }

  function scrollToRow(index) {
    if (index < 0) return
    // callLater: the model may just have changed, delegates still settling
    Qt.callLater(function() { positionViewAtIndex(index, ListView.Contain) })
  }

  // Hover moves the cursor only when the pointer itself moved: a rebuilt or
  // scrolled list slides rows under a still pointer, and each one used to
  // grab the cursor (the filter jumped it to row 27). Measured against the
  // viewport, so scrolling isn't movement.
  PointerMoveGate {
    id: pointerGate
    referenceItem: list
  }

  // Empty spacer: reserves exactly the stable header's height so delegates
  // begin below it. Gap math: the view adds `spacing` (2) after the header;
  // the old Column had 12 around the list.
  header: Item {
    width: list.width
    height: head.implicitHeight + Style.space(12) - list.spacing
  }

  // The stable header content. Direct children of a ListView live in its
  // contentItem, so this scrolls with the rows from content y=0 (above the
  // spacer) — and survives every model rebuild, keeping filter focus.
  Column {
    id: head
    z: 1  // above the spacer and freshly created delegates
    width: list.width
    spacing: Style.space(12)

    Loader {
      // follows the loaded Column's height (its root binds height:
      // implicitHeight), so a late-appearing setup card still grows
      width: parent.width
      sourceComponent: list.preamble
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

      Text {
        id: headerImport
        visible: !!list.pickedProvider && !!list.pickedProvider.importer
        anchors.right: pingButton.left
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
        text: "\uf021"  // nf-fa-refresh
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
      id: filterInput
      width: parent.width
      foreground: list.host.foreground
      placeholderText: "Filter servers — press /, Enter to apply"
      text: list.host.serverFilter
      onAccepted: {
        if (text !== list.host.serverFilter) {
          list.host.keyboardCursor = true
          list.host.serverCursor = 0
          list.host.serverFilter = text  // final op: rebuilds the model
          return
        }
        list.host.activateServerRow(list.host.serverRows[Math.max(0, list.host.serverCursor)])
      }
      Keys.onPressed: function(event) {
        if (event.key === Qt.Key_Down) { list.host.moveServerCursor(1); event.accepted = true }
        else if (event.key === Qt.Key_Up) { list.host.moveServerCursor(-1); event.accepted = true }
        else if (event.key === Qt.Key_Escape) {
          text = ""  // local first…
          if (list.keyTarget) list.keyTarget.forceActiveFocus()  // …then focus…
          list.host.keyboardCursor = false
          list.host.serverCursor = -1
          list.host.serverFilter = ""  // …then the rebuild-triggering write
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
  }

  footer: Item {
    width: list.width
    height: list.tail ? foot.implicitHeight + Style.space(12) - list.spacing : 0

    Column {
      id: foot
      width: parent.width
      spacing: Style.space(12)

      Loader {
        width: parent.width
        sourceComponent: list.tail
      }
    }
  }
}
