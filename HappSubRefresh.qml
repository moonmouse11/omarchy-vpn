import QtQuick
import qs.Commons
import qs.Ui

// ⟳ on a Happ/INCY protocol row or the SERVERS header (tabs): refresh subscription caches.
Item {
  id: root
  property var host: null
  property string provider: "Happ"

  implicitWidth: refreshText.implicitWidth
  implicitHeight: refreshText.implicitHeight

  Text {
    id: refreshText
    textFormat: Text.PlainText
    text: ""  // nf-fa-refresh
    color: refreshMouse.containsMouse ? root.host.foreground : root.host.dim
    font.family: root.host ? root.host.fontFamily : Style.font.family
    font.pixelSize: Style.font.caption
  }

  MouseArea {
    id: refreshMouse
    anchors.fill: parent
    anchors.margins: -Style.space(4)
    enabled: root.host !== null
    hoverEnabled: enabled
    cursorShape: Qt.PointingHandCursor
    onClicked: function(mouse) {
      mouse.accepted = true
      if (root.provider === "INCY") root.host.refreshIncySubscriptions()
      else root.host.refreshHappSubscriptions()
      root.host.loadServers()
    }
  }

  PanelToolTip {
    visible: refreshMouse.containsMouse
    text: root.provider === "INCY"
      ? "Fetch every INCY subscription from its provider now"
      : "Fetch every Happ subscription from its provider now"
    fontFamily: root.host ? root.host.fontFamily : Style.font.family
  }
}
