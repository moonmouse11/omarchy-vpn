import QtQuick
import Quickshell
import qs.Commons

// A check started from the bar panel (its Tools, the DNS badge, `d`): just
// the check card in a small window of its own — the whole app window behind
// it was one window too many to close. Same state as the app window's card.
FloatingWindow {
  id: win
  property var host: null

  title: "VPN Check"
  color: Color.background
  implicitWidth: 640
  implicitHeight: 560
  minimumSize: Qt.size(420, 320)
  visible: false  // Widget.openCheck(…, true) shows it; Close/Esc or Hyprland hides it

  onVisibleChanged: if (visible) card.focusKeys()

  CheckCard {
    id: card
    anchors.fill: parent
    host: win.host
    standalone: true
  }
}
