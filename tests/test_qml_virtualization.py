"""Structural pins for the virtualized panel/window server surfaces (Task 6)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_LIST = (ROOT / "ServerList.qml").read_text()
WIDGET = (ROOT / "Widget.qml").read_text()
APP = (ROOT / "AppWindow.qml").read_text()


def test_server_list_is_a_listview_without_repeater():
    assert re.search(r"^ListView\s*\{", SERVER_LIST, re.M)
    assert "Repeater" not in SERVER_LIST


def test_server_list_model_empties_while_inactive():
    # a hidden panel/window owns no ServerRow delegates at all
    assert re.search(r"property bool active", SERVER_LIST)
    assert "model: active ? host.serverRows : []" in SERVER_LIST


def test_server_list_scrolls_and_resets_by_index():
    assert "function scrollToRow" in SERVER_LIST
    assert "positionViewAtIndex" in SERVER_LIST
    assert "function resetPointer" in SERVER_LIST


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


def test_no_focus_recreation_lifecycle_remains():
    # VM round 3 proved focus restoration after header recreation is too late
    # — the stable-header design deletes that machinery entirely
    assert "filterEditing" not in SERVER_LIST
    assert "Component.onCompleted" not in SERVER_LIST
    assert "Component.onDestruction" not in SERVER_LIST
    assert "onActiveFocusChanged" not in SERVER_LIST
    assert "function focusFilter()" in SERVER_LIST


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


def test_escape_orders_clear_focus_handoff_then_rebuild():
    esc = SERVER_LIST.split("Key_Escape", 1)[1]
    assert esc.index('text = ""') < esc.index("forceActiveFocus")
    assert esc.index("forceActiveFocus") < esc.index('list.host.serverFilter = ""')
    assert "serverCursor = -1" in esc
