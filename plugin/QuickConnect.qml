import QtQuick
import qs.Commons
import qs.Ui

// QUICK CONNECT above SERVERS (panel and window): ★ favourites, then ⏲ the
// last few servers (--servers' `quick`, quickconnect.py). A click connects;
// the connected one is highlighted. Hidden while there is nothing to show.
Column {
  id: quick
  property var host: null
  readonly property var chips: (host.quick.favourites || []).map(function(c) {
    return { chip: c, star: true }
  }).concat((host.quick.recent || []).map(function(c) { return { chip: c, star: false } }))

  visible: chips.length > 0
  height: visible ? implicitHeight : 0
  spacing: Style.space(8)

  PanelSectionHeader {
    text: "QUICK CONNECT"
    foreground: quick.host.foreground
    fontFamily: quick.host.fontFamily
  }

  Flow {
    width: parent.width
    spacing: Style.space(8)

    Repeater {
      model: quick.chips
      Button {
        required property var modelData
        // nf-fa-star / nf-fa-clock_o
        text: (modelData.star ? " " : " ") + modelData.chip.name
        selected: modelData.chip.active === true
        bordered: true
        foreground: quick.host.foreground
        fontFamily: quick.host.fontFamily
        fontSize: Style.font.bodySmall
        tooltipText: modelData.chip.group + (modelData.chip.ping ? " · " + modelData.chip.ping : "")
        onClicked: if (!modelData.chip.active) quick.host.quickConnect(modelData.chip)
      }
    }
  }
}
