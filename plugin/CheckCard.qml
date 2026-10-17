import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Ui

// The app window's check card, over the window (the user's pick): DNS Leak
// Test, IP Info, Speed Test (--check, Widget.checkProc). Speed asks first —
// every service, one of them, or a custom URL. The state lives on the
// Widget, so a check outlives a closed window and shows when it reopens.
// Esc closes, r runs it again.
Item {
  id: card
  property var host: null
  readonly property bool urlFocused: urlField.activeFocus
  readonly property var titles: ({ dns: "DNS Leak Test", ip: "IP Info", speed: "Speed Test" })
  readonly property string phase: host.checkPhase

  visible: host.checkOpen

  function focusKeys() { Qt.callLater(function() { keys.forceActiveFocus() }) }

  function runAgain() {
    if (phase === "running") return
    if (host.checkKind === "speed" && host.checkTarget === "") host.openCheck("speed")
    else host.runCheck(host.checkKind, host.checkTarget)
  }

  function measureUrl() {
    var url = urlField.text.trim()
    if (url === "") return
    urlField.text = ""
    host.runCheck("speed", url)
    focusKeys()
  }

  Rectangle {
    anchors.fill: parent
    color: Util.alpha(Color.background, 0.7)
    MouseArea { anchors.fill: parent; onClicked: card.host.closeCheck() }
  }

  Item {
    id: keys
    anchors.fill: parent
    Keys.onPressed: function(event) {
      if (event.key === Qt.Key_Escape) { card.host.closeCheck(); event.accepted = true }
      else if (event.text.toLowerCase() === "r") { card.runAgain(); event.accepted = true }
    }
  }

  BorderSurface {
    id: box
    anchors.centerIn: parent
    width: Math.min(parent.width - Style.space(48), Style.space(620))
    height: Math.min(parent.height - Style.space(48), body.implicitHeight + Style.space(32))
    // opaque: a theme's background may carry alpha, and the window showed through
    color: Qt.rgba(Color.background.r, Color.background.g, Color.background.b, 1)
    borderSpec: Border.controlSpec("normal", card.host.foreground, Color.accent)
    radius: Style.cornerRadius

    MouseArea { anchors.fill: parent; onClicked: {} }  // a click inside doesn't close

    Flickable {
      anchors.fill: parent
      anchors.margins: Style.space(16)
      contentWidth: width
      contentHeight: body.implicitHeight
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

      Column {
        id: body
        width: parent.width - Style.space(8)
        spacing: Style.space(10)

        // ── title + actions ────────────────────────────────────────────
        Item {
          width: parent.width
          implicitHeight: Math.max(title.implicitHeight, actions.implicitHeight)

          Text {
            id: title
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            textFormat: Text.PlainText
            text: (card.titles[card.host.checkKind] || "")
              + (card.phase === "done" && card.host.checkAt > 0
                ? "  ·  " + Qt.formatTime(new Date(card.host.checkAt), "HH:mm") : "")
            color: card.host.foreground
            font.family: card.host.fontFamily
            font.pixelSize: Style.font.body
            font.bold: true
          }

          Row {
            id: actions
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(8)

            Button {
              visible: card.phase === "done" || card.phase === "error"
              text: "Run again"
              bordered: true
              foreground: card.host.foreground
              fontFamily: card.host.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: card.runAgain()
            }
            Button {
              text: "Close"
              bordered: true
              foreground: card.host.foreground
              fontFamily: card.host.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: card.host.closeCheck()
            }
          }
        }

        // ── speed: what to measure ─────────────────────────────────────
        Flow {
          visible: card.phase === "choose"
          width: parent.width
          spacing: Style.space(8)

          Repeater {
            model: card.host.checkChoices
            Button {
              required property var modelData
              text: modelData.label
              bordered: true
              foreground: card.host.foreground
              fontFamily: card.host.fontFamily
              fontSize: Style.font.bodySmall
              onClicked: card.host.runCheck("speed", modelData.key)
            }
          }
        }

        Row {
          visible: card.phase === "choose"
          width: parent.width
          spacing: Style.space(8)

          TextField {
            id: urlField
            width: parent.width - measureButton.width - parent.spacing
            foreground: card.host.foreground
            placeholderText: "Custom URL (http/https, a large file)"
            onAccepted: card.measureUrl()
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) { card.focusKeys(); event.accepted = true }
            }
          }
          Button {
            id: measureButton
            text: "Measure"
            bordered: true
            foreground: card.host.foreground
            fontFamily: card.host.fontFamily
            fontSize: Style.font.bodySmall
            onClicked: card.measureUrl()
          }
        }

        // ── progress ───────────────────────────────────────────────────
        Text {
          visible: card.phase === "running" || (card.phase === "choose" && card.host.checkChoices.length === 0)
          width: parent.width
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: {
            var p = card.host.checkProgress
            if (!p) return "Starting…"
            return (p.steps ? p.step + "/" + p.steps + " · " : "") + p.label
          }
          color: card.host.dim
          font.family: card.host.fontFamily
          font.pixelSize: Style.font.bodySmall
        }

        // ── result ─────────────────────────────────────────────────────
        Text {
          visible: card.phase === "error"
          width: parent.width
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: card.host.checkError
          color: card.host.urgent
          font.family: card.host.fontFamily
          font.pixelSize: Style.font.bodySmall
          font.bold: true
        }

        Text {
          readonly property var summary: card.host.checkResult ? card.host.checkResult.summary : null
          visible: card.phase === "done" && summary !== null
          width: parent.width
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: !summary ? ""
            : (summary.state ? card.host.badgeGlyph(summary.state) + "  " : "") + summary.text
          color: summary && summary.state === "bad" ? card.host.urgent : card.host.foreground
          font.family: card.host.fontFamily
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Repeater {
          model: card.phase === "done" && card.host.checkResult ? card.host.checkResult.rows : []
          Text {
            required property var modelData
            width: body.width
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: modelData.text
            color: modelData.state === "bad" ? card.host.urgent : card.host.foreground
            font.family: card.host.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: modelData.state === "bad"
          }
        }
      }
    }
  }
}
