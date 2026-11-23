import json

import pytest

import clipboardread
import logutil
import vpn_manager


@pytest.mark.parametrize(
    ("preset", "limit"),
    [("filter", 4096), ("url", 8192), ("key", 65536)],
)
def test_clipboard_cli_uses_fixed_byte_limit(monkeypatch, capsys, preset, limit):
    secret = "секретное значение"
    seen = []
    logs = []
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--clipboard", preset])
    monkeypatch.setattr(clipboardread, "read_text", lambda value: seen.append(value) or secret)
    monkeypatch.setattr(logutil, "log", logs.append)

    vpn_manager.main()

    assert seen == [limit]
    assert json.loads(capsys.readouterr().out) == {"text": secret}
    assert secret not in vpn_manager.sys.argv
    assert logs == []


def test_clipboard_cli_reports_reader_failure_without_logging(monkeypatch, capsys):
    logs = []
    monkeypatch.setattr(vpn_manager.sys, "argv", ["vpn_manager.py", "--clipboard", "filter"])
    monkeypatch.setattr(
        clipboardread,
        "read_text",
        lambda _limit: (_ for _ in ()).throw(clipboardread.ClipboardReadError("too large")),
    )
    monkeypatch.setattr(logutil, "log", logs.append)

    with pytest.raises(SystemExit) as exit_info:
        vpn_manager.main()

    assert exit_info.value.code == 1
    assert json.loads(capsys.readouterr().out) == {"error": "too large"}
    assert logs == []
