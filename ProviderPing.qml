import QtQuick
import qs.Commons
import qs.Ui

// ⟳ ping every server of one protocol (Happ or INCY) — the provider row in tree layout.
Item {
  id: root
  property var host: null
  property string provider: ""

  implicitWidth: pingText.implicitWidth
  implicitHeight: pingText.implicitHeight

  Text {
    id: pingText
    textFormat: Text.PlainText
    text: ""  // nf-fa-plug — distinct from subscription refresh ⟳
    color: pingMouse.containsMouse ? root.host.foreground : root.host.dim
    font.family: root.host ? root.host.fontFamily : Style.font.family
    font.pixelSize: Style.font.caption
  }

  MouseArea {
    id: pingMouse
    anchors.fill: parent
    anchors.margins: -Style.space(4)
    enabled: root.host !== null && root.provider !== ""
    hoverEnabled: enabled
    cursorShape: Qt.PointingHandCursor
    onClicked: function(mouse) {
      mouse.accepted = true
      root.host.pingProvider(root.provider)
    }
  }

  PanelToolTip {
    visible: pingMouse.containsMouse
    text: "Ping every " + root.provider + " server"
    fontFamily: root.host ? root.host.fontFamily : Style.font.family
  }
}
