"""Structural pins for the virtualized panel/window server surfaces (Task 6)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_LIST = (ROOT / "ServerList.qml").read_text()
WIDGET = (ROOT / "Widget.qml").read_text()
APP = (ROOT / "AppWindow.qml").read_text()
SERVER_ROW = (ROOT / "ServerRow.qml").read_text()


def test_server_list_is_a_listview_without_repeater():
    assert re.search(r"^ListView\s*\{", SERVER_LIST, re.M)
    assert "Repeater" not in SERVER_LIST


def test_open_panel_freezes_the_bar_label_that_defines_its_anchor_geometry():
    assert "property bool panelBarLabelCaptured: false" in WIDGET
    assert 'property string panelBarLabel: ""' in WIDGET
    assert "opened && panelBarLabelCaptured ? panelBarLabel : barLabel" in WIDGET
    assert "panelBarLabel = barLabel" in WIDGET
    button = WIDGET.split("WidgetButton {", 1)[1].split("KeyboardPanel {", 1)[0]
    assert "root.displayedBarLabel" in button
    assert "root.barLabel" not in button


def test_server_list_model_empties_while_inactive_without_replacing_the_model_array():
    # A numeric model keeps existing delegates alive when --servers replaces
    # the JavaScript array with the same number of rows. Hidden lists own none.
    assert re.search(r"property bool active", SERVER_LIST)
    assert "model: active ? host.serverRows.length : 0" in SERVER_LIST
    assert "row: list.host.serverRows[index]" in SERVER_LIST
    assert "model: active ? host.serverRows : []" not in SERVER_LIST


def test_server_list_scrolls_and_resets_by_index():
    assert "function scrollToRow" in SERVER_LIST
    assert "positionViewAtIndex" in SERVER_LIST
    assert "function resetPointer" in SERVER_LIST


def test_model_rebuilds_preserve_every_visible_viewport():
    assert "function rememberViewport" in SERVER_LIST
    assert "function restoreViewport" in SERVER_LIST
    assert "host.rowIdentity" in SERVER_LIST
    assert "function rememberViewports" in WIDGET
    remembered = WIDGET.split("function rememberViewports", 1)[1].split("function setExpanded", 1)[
        0
    ]
    assert "panelList.rememberViewport" in remembered
    assert "appWindow.locations.rememberViewport" in remembered

    expanded = WIDGET.split("function setExpanded", 1)[1].split("function rowOpenKey", 1)[0]
    assert "rememberViewports" in expanded
    assert expanded.index("rememberViewports") < expanded.index("expandedGroups = next")

    loaded = WIDGET.split("id: serversProc", 1)[1].split("id: pingSettle", 1)[0]
    assert "root.rememberViewports()" in loaded
    assert loaded.index("root.rememberViewports()") < loaded.index("root.serverGroups =")

    changed = WIDGET.split("onServerRowsChanged:", 1)[1].split("AppWindow {", 1)[0]
    assert "panelList.restoreViewport()" in changed
    assert "appWindow.locations.restoreViewport()" in changed


def test_fold_restore_is_anchored_to_the_clicked_header():
    assert "function rowIdentity" in WIDGET
    assert "function rowIndex" in WIDGET
    assert "setExpanded(rowOpenKey(row), !row.open, row)" in WIDGET
    assert "setExpanded(rowOpenKey(row), open, row)" in WIDGET


def test_inactive_list_cannot_reuse_a_stale_viewport_anchor():
    remember = SERVER_LIST.split("function rememberViewport", 1)[1].split(
        "function boundedContentY", 1
    )[0]
    assert "savedViewport = null" in remember
    restore = SERVER_LIST.split("function restoreViewport", 1)[1].split("// Hover moves", 1)[0]
    assert "if (!active)" in restore
    assert "savedViewport = null" in restore


def test_deferred_restore_cannot_overwrite_a_newer_viewport_snapshot():
    restore = SERVER_LIST.split("function restoreViewport", 1)[1].split("// Hover moves", 1)[0]
    inner = restore.split("Qt.callLater(function()", 2)[2]
    assert "savedViewport !== saved" in inner
    assert inner.index("savedViewport !== saved") < inner.index("contentY =")


def test_server_list_exposes_preamble_tail_filter_and_gate():
    assert "property Component preamble" in SERVER_LIST
    assert "property Component tail" in SERVER_LIST
    # the filter field is a stable direct child of the view (model rebuilds
    # never destroy it), so a plain root alias is safe
    assert "readonly property alias filterField: filterInput" in SERVER_LIST
    # hover gate measured against the list itself (the viewport)
    assert "referenceItem: list" in SERVER_LIST
    assert "ScrollBar.vertical" in SERVER_LIST


def test_panel_list_active_only_while_open():
    assert WIDGET.count("active: root.opened") == 1
    # the outer Flickable+Column wrapper is gone; the panel still fits content
    assert "panelFlick" not in WIDGET
    assert "panelList.contentHeight" in WIDGET
    assert "fittedContentHeight" in WIDGET


def test_panel_supplies_preamble_and_tail_and_resets_on_open():
    assert "preamble:" in WIDGET
    assert "tail:" in WIDGET
    assert "panelList.positionViewAtBeginning()" in WIDGET


def test_app_window_list_active_without_outer_flickable():
    assert "locationsFlick" not in APP
    # Visibility, not keyboard ownership: the panel may be open at the same time.
    assert re.search(r"active:\s*win\.host\.windowOpen\s*$", APP, re.M)


def test_header_is_a_spacer_and_the_filter_field_is_stable():
    # the header: Component is an empty spacer reserving the stable header
    # column's height — it holds no focusable content (the view may recreate
    # it on model rebuilds, which is harmless for an empty Item)
    m = re.search(r"header: Item \{(.*?)\n  \}", SERVER_LIST, re.S)
    assert m, "header must be a plain Item spacer"
    header_block = m.group(1)
    assert "TextField" not in header_block
    assert "head.implicitHeight" in header_block
    # the real header column (with the TextField) is a direct child of the view
    assert re.search(r"^  Column \{\n    id: head", SERVER_LIST, re.M)
    assert "TextField" in SERVER_LIST


def test_stable_header_is_parented_and_positioned_by_scroll_header():
    head = SERVER_LIST.split("id: head", 1)[1].split("Loader {", 1)[0]
    assert "parent: list.contentItem" in head
    assert "y: list.headerItem ? list.headerItem.y : 0" in head


def test_no_focus_recreation_lifecycle_remains():
    # VM round 3 proved focus restoration after header recreation is too late
    # — the stable-header design deletes that machinery entirely
    assert "filterEditing" not in SERVER_LIST
    assert "Component.onCompleted" not in SERVER_LIST
    assert "Component.onDestruction" not in SERVER_LIST
    assert "onActiveFocusChanged" not in SERVER_LIST
    assert "function focusFilter()" in SERVER_LIST


def test_subscription_refresh_is_the_only_provider_header_action():
    assert "HappSubRefresh {" in SERVER_ROW
    assert "ProviderPing {" not in SERVER_ROW
    assert "id: groupPing" not in SERVER_ROW
    assert "host.pingProvider" not in SERVER_ROW


def test_ping_action_exists_only_in_the_servers_header():
    assert SERVER_LIST.count('onClicked: list.host.run("--ping-now")') == 1
    assert "id: pingMouse" not in SERVER_ROW
    assert "host.pingRow(" not in SERVER_ROW
    assert 'k === "p") root.run("--ping-now")' in WIDGET
    assert 'k === "p") win.host.run("--ping-now")' in APP
    assert "serverRow.rightText" in SERVER_ROW


def test_ping_button_glyph_is_the_escaped_refresh():
    # the literal PUA glyph doesn't survive editor/tool round trips — pin the
    # escaped spelling (review: the rewrite once lost it to an empty string)
    assert 'text: "\\uf021"' in SERVER_LIST


def test_no_direct_filter_field_focus_callers():
    assert "filterField.forceActiveFocus()" not in WIDGET
    assert "filterField.forceActiveFocus()" not in APP
    assert "panelList.focusFilter()" in WIDGET
    assert "locations.focusFilter()" in APP


def test_typing_never_rebuilds_the_model():
    # user-approved semantics: the filter applies on Enter, not per character
    assert "onTextChanged" not in SERVER_LIST
    assert "Enter to apply" in SERVER_LIST  # placeholder says so


def test_enter_applies_before_activating():
    accepted = SERVER_LIST.split("onAccepted:", 1)[1]
    assert "text !== list.host.serverFilter" in accepted
    # a changed text only applies the filter (cursor state, then the
    # serverFilter write as the final operation) and returns — the NEXT
    # Enter on an already-applied filter activates the current/first row
    assert accepted.index("list.host.serverFilter = text") < accepted.index("return")
    assert accepted.index("return") < accepted.index("activateServerRow")


def test_force_switch_uses_one_result_aware_process_and_retains_target():
    assert "id: connectProc" in WIDGET
    assert 'startConnect("--connect-result")' in WIDGET
    assert 'startConnect("--force-connect")' in WIDGET
    assert "property var forceTarget" in WIDGET
    assert "property bool forceConfirmOpen" in WIDGET
    assert "property string forceMessage" in WIDGET
    connect = WIDGET.split("function connectServer", 1)[1].split("function moveServerCursor", 1)[0]
    assert 'runArgs(["--connect"' not in connect
    assert "subscription_id" in connect


def test_newest_connect_click_replaces_the_running_result_process():
    assert "replacePending" in WIDGET
    assert "ignoreResult" in WIDGET
    assert "connectProc.running = false" in WIDGET
    assert "if (connectProc.running || forceConfirmOpen) return" not in WIDGET
    exited = WIDGET.split("id: connectProc", 1)[1].split("id: checkProc", 1)[0]
    assert "Qt.callLater" in exited
    assert 'startConnect("--connect-result")' in exited


def test_force_dialog_focus_returns_to_any_existing_delete_confirmation():
    changed = APP.split("function onForceConfirmOpenChanged()", 1)[1].split("}", 1)[0]
    assert "deleteConfirmOpen" in changed
    assert "confirmKeys.forceActiveFocus()" in changed


def test_force_confirmation_is_shared_by_panel_and_window():
    assert "opened: root.forceConfirmOpen" in WIDGET
    assert "onConfirmed: root.confirmForceSwitch()" in WIDGET
    assert "onCanceled: root.cancelForceSwitch()" in WIDGET
    assert "opened: win.host.forceConfirmOpen" in APP
    assert "onConfirmed: win.host.confirmForceSwitch()" in APP
    assert "onCanceled: win.host.cancelForceSwitch()" in APP


def test_escape_orders_clear_focus_handoff_then_rebuild():
    esc = SERVER_LIST.split("Key_Escape", 1)[1]
    assert esc.index('text = ""') < esc.index("forceActiveFocus")
    assert esc.index("forceActiveFocus") < esc.index('list.host.serverFilter = ""')
    assert "serverCursor = -1" in esc
