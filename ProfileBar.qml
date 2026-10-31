import QtQuick
import qs.Commons
import qs.Ui

// The app window's Profiles strip above Locations (host.profileMode):
// "import" — a protocol's "+ Import": a config path or the desktop file
// chooser, or a pasted VLESS/SS key; "profile" — a server's right click (or
// a / x): Toggle autostart, Delete….
Column {
  id: bar
  property var host: null
  readonly property bool importing: host.profileMode === "import"
  readonly property var target: host.profileTarget
  readonly property bool keyImport: importing && target !== null && target.importer === "key"
  readonly property bool inputFocused: input.activeFocus
  readonly property bool subscriptionProfile: host.profileMode === "subscription"
  readonly property bool profileActive: !importing && target !== null && target.server && target.server.active === true
  readonly property bool canManage: !importing && target !== null && bar.host.providerInfo(target.group.provider) && bar.host.providerInfo(target.group.provider).manage === true
  readonly property bool canAutostart: canManage && bar.host.providerInfo(target.group.provider).autostart === true

  visible: host.profileMode !== ""
  height: visible ? implicitHeight : 0
  spacing: Style.space(8)

  function focusInput() {
    input.text = ""
    if (importing) Qt.callLater(function() { input.forceActiveFocus() })
  }

  function submit() {
    if (input.text.trim() === "") return
    if (keyImport) host.importKey(input.text)
    else host.importFile(input.text.trim())
    input.text = ""
  }

  Text {
    width: parent.width
    textFormat: Text.PlainText
    elide: Text.ElideRight
    text: !bar.target ? ""
      : bar.importing ? "Import " + bar.target.name + (bar.keyImport ? " key" : " config")
      : bar.target.server ? bar.target.server.name + " · " + bar.target.group.provider : ""
    color: bar.host.foreground
    font.family: bar.host.fontFamily
    font.pixelSize: Style.font.bodySmall
    font.bold: true
  }

  TextField {
    id: input
    visible: bar.importing
    width: parent.width
    foreground: bar.host.foreground
    // a key is a password: never shown, never in argv (stdin, see Widget.importKey)
    password: bar.keyImport
    placeholderText: bar.keyImport ? "Paste a vless:// or ss:// key" : "Path to the config file"
    onAccepted: bar.submit()
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape) { bar.host.closeProfileBar(); event.accepted = true }
    }
  }

  Flow {
    width: parent.width
    spacing: Style.space(8)

    Button {
      visible: bar.importing && !bar.keyImport
      text: "Choose file…"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.host.importFile("")
    }
    Button {
      visible: bar.importing
      text: "Import"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.submit()
    }
    Button {
      visible: bar.profileActive
      text: "Disconnect"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.host.profileDisconnect()
    }
    Button {
      visible: !bar.importing && !bar.profileActive && bar.canAutostart
      text: "Toggle autostart"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.host.profileAction("autostart")
    }
    Button {
      visible: !bar.importing && !bar.profileActive && bar.canManage
      text: "Delete…"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.host.deleteConfirmOpen = true
    }
    Button {
      text: "Cancel"
      bordered: true
      foreground: bar.host.foreground
      fontFamily: bar.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: bar.host.closeProfileBar()
    }
  }
}
