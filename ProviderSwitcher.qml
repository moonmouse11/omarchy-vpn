import QtQuick
import qs.Commons
import qs.Ui

// The protocol picker of the app window's "tabs" (a row above the list) and
// "sidebar" (a column left of it) layouts — ⚙ Settings → "Protocols in the
// VPN window". "" = All; [ / ] step through it from the keyboard.
Flow {
  id: switcher
  property var host: null
  property bool vertical: false

  flow: vertical ? Flow.TopToBottom : Flow.LeftToRight
  spacing: Style.space(vertical ? 4 : 8)

  Repeater {
    model: switcher.host.providerChoices
    Button {
      required property var modelData
      width: switcher.vertical ? switcher.width : implicitWidth
      leftAlign: switcher.vertical
      text: modelData.name === "" ? "All"
        : modelData.name + "  " + modelData.total + (modelData.active ? " ●" : "")
      selected: switcher.host.providerFilter === modelData.name
      bordered: true
      foreground: switcher.host.foreground
      fontFamily: switcher.host.fontFamily
      fontSize: Style.font.bodySmall
      onClicked: switcher.host.providerFilter = modelData.name
    }
  }
}
