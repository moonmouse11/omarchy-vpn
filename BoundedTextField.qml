import QtQuick
import Quickshell
import Quickshell.Io
import qs.Ui

TextField {
  id: root

  property string backend: ""
  property string pasteKind: "filter"
  property int requestGeneration: 0

  signal pasteFailed(string reason)
  signal unhandledKeyPressed(var event)

  function insertBounded(value) {
    var start = root.selectionStart
    var end = root.selectionEnd
    var available = Math.max(0, root.maximumLength - (root.text.length - (end - start)))
    var addition = String(value).slice(0, available)
    if (addition.length === 0) return
    if (end > start) root.remove(start, end)
    root.insert(start, addition)
    root.cursorPosition = start + addition.length
  }

  function handlePasteResult(generation, output) {
    if (generation !== root.requestGeneration) return
    pasteProc.resultSeen = true
    var data = null
    try { data = JSON.parse(String(output || "")) } catch (error) {}
    if (data && typeof data.text === "string") root.insertBounded(data.text)
    else root.pasteFailed(data && data.error ? String(data.error) : "clipboard unavailable")
  }

  function startPaste() {
    pasteProc.generation = requestGeneration
    pasteProc.resultSeen = false
    pasteProc.running = true
  }

  function requestBoundedPaste() {
    requestGeneration += 1
    if (pasteProc.running) {
      pasteProc.restartPending = true
      pasteProc.running = false
      return
    }
    startPaste()
  }

  Keys.onShortcutOverride: function(event) {
    if (event.matches(StandardKey.Paste)) event.accepted = true
  }

  Keys.onPressed: function(event) {
    if (event.matches(StandardKey.Paste)) {
      event.accepted = true
      root.requestBoundedPaste()
    } else {
      root.unhandledKeyPressed(event)
    }
  }

  TapHandler {
    acceptedButtons: Qt.RightButton | Qt.MiddleButton
    gesturePolicy: TapHandler.ReleaseWithinBounds
    onTapped: root.requestBoundedPaste()
  }

  Process {
    id: pasteProc
    command: ["python3", root.backend, "--clipboard", root.pasteKind]
    property int generation: 0
    property bool resultSeen: false
    property bool restartPending: false

    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.handlePasteResult(pasteProc.generation, text)
    }

    onExited: {
      if (restartPending) {
        restartPending = false
        Qt.callLater(function() {
          if (!pasteProc.running) root.startPaste()
        })
      } else if (generation === root.requestGeneration && !resultSeen) {
        root.pasteFailed("clipboard unavailable")
      }
    }
  }
}
