import QtQuick
import qs.Commons
import qs.Ui

// ⟳ on the Happ protocol row or the SERVERS header (tabs): fetch every subscription.
Item {
  id: root
  property var host: null

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
    onClicked: {
      root.host.refreshHappSubscriptions()
      root.host.loadServers()
    }
  }

  PanelToolTip {
    visible: refreshMouse.containsMouse
    text: "Fetch every Happ subscription from its provider now"
    fontFamily: root.host ? root.host.fontFamily : Style.font.family
  }
}
