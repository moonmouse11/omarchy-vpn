import QtQuick
import qs.Commons
import qs.Ui

// Hero (state + connection + the power switch), exit/traffic lines and the
// PROTECTION badges — the bar panel's top and the app window's Connection.
Column {
  id: summary
  property var host: null

  spacing: Style.space(12)

  Item {
    width: parent.width
    implicitHeight: hero.implicitHeight

    PanelHero {
      id: hero
      width: parent.width
      title: String(summary.host.panelData.title || "VPN")
      meta: String(summary.host.panelData.meta || "")
      detail: String(summary.host.panelData.detail || "")
      foreground: summary.host.foreground
      fontFamily: summary.host.fontFamily
      iconComponent: Component {
        Text {
          text: summary.host.stateGlyph
          color: summary.host.atRisk ? summary.host.urgent
            : (summary.host.connected ? summary.host.foreground : summary.host.dim)
          font.family: summary.host.fontFamily
          font.pixelSize: Style.font.display
        }
      }
      trailingControl: Component {
        ToggleSwitch {
          id: powerSwitch
          checked: summary.host.connected
          busy: summary.host.busy
          foreground: hero.foreground
          onToggled: summary.host.togglePower()

          PanelToolTip {
            visible: powerSwitch.containsMouse
            text: summary.host.connected ? "Disconnect all VPNs"
              : summary.host.cursorServerRow() ? "Connect the selected server"
              : summary.host.quick.last ? "Connect " + summary.host.quick.last.name
              : "Choose a server below"
            fontFamily: hero.fontFamily
          }
        }
      }
    }
  }

  Item {
    width: parent.width
    implicitHeight: exitText.implicitHeight
    visible: exitText.text !== ""

    Text {
      id: exitText
      textFormat: Text.PlainText
      width: parent.width
      text: summary.host.exitLine
      color: exitMouse.enabled && exitMouse.containsMouse ? summary.host.foreground : summary.host.dim
      font.family: summary.host.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    MouseArea {
      id: exitMouse
      anchors.fill: parent
      enabled: summary.host.exitIpCopy !== ""
      hoverEnabled: enabled
      cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
      onClicked: summary.host.copyToClipboard(summary.host.exitIpCopy)
    }

    PanelToolTip {
      visible: exitMouse.enabled && exitMouse.containsMouse
      text: "Copy " + summary.host.exitIpCopy
      fontFamily: summary.host.fontFamily
    }
  }

  Text {
    textFormat: Text.PlainText
    visible: text !== ""
    width: parent.width
    text: summary.host.trafficLine
    color: summary.host.dim
    font.family: summary.host.fontFamily
    font.pixelSize: Style.font.bodySmall
    elide: Text.ElideRight
  }

  PanelSeparator { foreground: summary.host.foreground }

  PanelSectionHeader {
    text: "PROTECTION"
    foreground: summary.host.foreground
    fontFamily: summary.host.fontFamily
  }

  Flow {
    width: parent.width
    spacing: Style.space(8)

    Repeater {
      model: summary.host.badges

      BorderSurface {
        id: badge
        required property var modelData
        readonly property bool actionable: modelData.id === "dns" && modelData.state !== "ok"
        implicitWidth: badgeRow.implicitWidth + Style.space(16)
        implicitHeight: badgeRow.implicitHeight + Style.space(8)
        color: badgeMouse.containsMouse && actionable
          ? Style.hoverFillFor(summary.host.foreground, Color.accent) : "transparent"
        borderSpec: Border.controlSpec("normal", summary.host.badgeColor(modelData.state),
          summary.host.badgeColor(modelData.state))
        radius: Style.cornerRadius

        Row {
          id: badgeRow
          anchors.centerIn: parent
          spacing: Style.space(6)

          Text {
            text: summary.host.badgeGlyph(badge.modelData.state)
            color: summary.host.badgeColor(badge.modelData.state)
            font.family: summary.host.fontFamily
            font.pixelSize: Style.font.caption
            anchors.verticalCenter: parent.verticalCenter
          }
          Text {
            textFormat: Text.PlainText
            text: String(badge.modelData.label || "")
            color: badge.modelData.state === "bad" ? summary.host.urgent
              : (badge.modelData.state === "ok" ? summary.host.foreground : summary.host.dim)
            font.family: summary.host.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: badge.modelData.state === "bad"
          }
        }

        MouseArea {
          id: badgeMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: badge.actionable ? Qt.PointingHandCursor : Qt.ArrowCursor
          onClicked: if (badge.actionable) summary.host.runDnsTest()
        }

        PanelToolTip {
          visible: badgeMouse.containsMouse && text !== ""
          text: String(badge.modelData.hint || "") + (badge.actionable ? " — click to run" : "")
          fontFamily: summary.host.fontFamily
        }
      }
    }
  }
}
