import QtQuick
import qs.Commons
import qs.Ui

// The Tools buttons — the app window's and the bar panel's. The three checks
// open the check card: over the app window there, in its own small window
// (CheckWindow.qml) from the panel (`standalone`); the rest run --tool KEY.
Flow {
  id: tools
  property var host: null
  property bool standalone: false

  readonly property var all: [
    { key: "dns_leak_test", label: "DNS leak test", check: "dns" },
    { key: "ip_info", label: "IP info", check: "ip" },
    { key: "speed_test", label: "Speed test", check: "speed" },
    { key: "clear_caches", label: "Clear caches" },
    { key: "killswitch", label: "Kill switch on/off" },
    { key: "settings", label: "Settings" }
  ]

  spacing: Style.space(8)

  Repeater {
    // ⚙ Settings hides tools; no kill switch under a NetworkManager VPN
    // (panel_state's "tools"; all of them before the first status)
    model: tools.all.filter(function(t) {
      var keys = tools.host.panelData.tools
      return !(keys instanceof Array) || keys.indexOf(t.key) !== -1
    })
    Button {
      required property var modelData
      text: modelData.label
      foreground: tools.host.foreground
      fontFamily: tools.host.fontFamily
      fontSize: Style.font.bodySmall
      bordered: true
      onClicked: {
        if (modelData.check) tools.host.openCheck(modelData.check, tools.standalone)
        else tools.host.runArgs(["--tool", modelData.key])
      }
    }
  }
}
