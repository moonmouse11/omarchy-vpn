import subprocess

import pytest

import config
import installwizard


class FakePrompter(installwizard.Prompter):
    """Feeds canned answers in call order — confirms and texts are two
    separate queues since the wizard interleaves them by section."""

    def __init__(self, confirms=(), texts=(), choices=()):
        self._confirms = iter(confirms)
        self._texts = iter(texts)
        self._choices = iter(choices)  # a list, or None = cancel; default: the preselection
        self.questions = []

    def choose(self, question, options, selected, multi=True):
        self.questions.append(question)
        return next(self._choices, list(selected))

    def confirm(self, question, default):
        return next(self._confirms, default)

    def text(self, question):
        return next(self._texts, "")


def test_terminal_prompter_confirm_default_on_empty_answer(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert installwizard.TerminalPrompter().confirm("Q?", default=True) is True
    assert installwizard.TerminalPrompter().confirm("Q?", default=False) is False


def test_terminal_prompter_confirm_explicit_answer(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert installwizard.TerminalPrompter().confirm("Q?", default=False) is True
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert installwizard.TerminalPrompter().confirm("Q?", default=True) is False


def test_terminal_prompter_text_strips_input(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    # text() now goes through getpass.getpass (not input()) so a typed API
    # key doesn't echo to the terminal/scrollback.
    monkeypatch.setattr(installwizard.getpass, "getpass", lambda prompt: "  secret-key  ")
    assert installwizard.TerminalPrompter().text("Key?") == "secret-key"


@pytest.mark.parametrize("exc", [KeyboardInterrupt, EOFError])
def test_ctrl_c_at_any_question_cancels_the_install(wizard, monkeypatch, exc):
    """Ctrl-C (or Ctrl-D) at a yes/no or API-key question cancels like Esc in
    gum: nothing saved, exit 1 (install.sh stops before sudo). Without a tty
    nothing is asked at all, so EOF here is always the user's."""
    monkeypatch.setattr(installwizard, "detect", detected())

    def interrupt(*args):
        raise exc

    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: None)  # yes/no fallback
    monkeypatch.setattr("builtins.input", interrupt)
    assert installwizard.run(installwizard.TerminalPrompter(), wizard / "packages") == 1
    assert not config.CONFIG_PATH.exists()

    class KeyInterrupt(FakePrompter):
        def text(self, question):
            raise exc

    assert installwizard.run(KeyInterrupt(), wizard / "packages") == 1
    assert not config.CONFIG_PATH.exists()
    assert not (wizard / "packages").exists()


class Tty:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


def test_choose_without_tty_returns_preselection(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(False))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted"))
    got = installwizard.TerminalPrompter().choose("Protocols", ["A", "B"], ["B"])
    assert got == ["B"]


def test_choose_uses_gum(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.CompletedProcess(cmd, 0, stdout="WireGuard\nHapp\n")

    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: "/usr/bin/gum")
    monkeypatch.setattr(installwizard.subprocess, "run", run)
    got = installwizard.TerminalPrompter().choose(
        "Protocols", ["WireGuard", "Happ", "X"], ["Happ", "X"]
    )
    assert got == ["WireGuard", "Happ"]
    ((cmd, kw),) = calls
    assert cmd[:2] == ["gum", "choose"]
    assert "--no-limit" in cmd
    # gum 2.x toggles with x/Tab, not Space: the header says so
    assert cmd[cmd.index("--header") + 1] == "Protocols  (x / Tab: toggle · Enter: done)"
    assert "--selected=Happ,X" in cmd
    assert cmd[cmd.index("--") + 1 :] == ["WireGuard", "Happ", "X"]
    assert kw["stdout"] == subprocess.PIPE  # the UI itself stays on the terminal


def test_choose_single_has_no_no_limit(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="Happ only\n")

    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: "/usr/bin/gum")
    monkeypatch.setattr(installwizard.subprocess, "run", run)
    prompter = installwizard.TerminalPrompter()
    assert prompter.choose(
        "KS", ["Every provider", "Happ only"], ["Every provider"], multi=False
    ) == ["Happ only"]
    assert "--no-limit" not in calls[0]


def test_choose_gum_cancel_is_none(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: "/usr/bin/gum")
    monkeypatch.setattr(
        installwizard.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 130, stdout=""),
    )
    assert installwizard.TerminalPrompter().choose("Q", ["A"], ["A"]) is None


def test_choose_falls_back_to_confirms(monkeypatch):
    answers = iter(["", "y", "n"])  # A: Enter keeps "selected", B: yes, C: no
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(True))
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: None)
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    assert installwizard.TerminalPrompter().choose("Q", ["A", "B", "C"], ["A", "C"]) == ["A", "B"]


def test_terminal_prompter_never_prompts_without_tty(monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(False))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted"))
    monkeypatch.setattr(installwizard.getpass, "getpass", lambda prompt: pytest.fail("prompted"))
    prompter = installwizard.TerminalPrompter()
    assert prompter.confirm("Q?", default=True) is True
    assert prompter.text("Key?") == ""


# ── the wizard ────────────────────────────────────────────────────────────────


class Source:
    def __init__(self, key, name, needs_api_key):
        self.key, self.name, self.needs_api_key = key, name, needs_api_key


@pytest.fixture
def wizard(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(
        installwizard.ipsources,
        "ALL_SOURCES",
        [Source("ipwhois", "ipwho.is", False), Source("abuseipdb", "AbuseIPDB", True)],
    )
    monkeypatch.setattr(installwizard, "missing_packages", lambda names: [])
    monkeypatch.setattr(installwizard.shutil, "which", lambda b: "/usr/bin/" + b)
    (tmp_path / "happd").write_text("")
    monkeypatch.setattr(installwizard, "HAPPD", tmp_path / "happd")
    return tmp_path


def detected(**notes):
    return lambda: installwizard.Detection(notes=notes)


def visible(cfg):
    return [p for p in installwizard.PROTOCOLS if cfg.provider_visible(p)]


def test_fresh_install_preselects_detected(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected(WireGuard="2 profiles", Happ="installed"))
    prompter = FakePrompter()
    assert installwizard.run(prompter, None) == 0
    assert visible(config.load_config()) == ["WireGuard", "Happ"]
    assert prompter.questions[0] == "Protocols"


def test_fresh_install_nothing_detected_shows_all(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    assert installwizard.run(FakePrompter(), None) == 0
    assert visible(config.load_config()) == installwizard.PROTOCOLS


def test_protocol_labels_carry_the_note(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected(WireGuard="2 profiles"))
    seen = {}

    class Spy(FakePrompter):
        def choose(self, question, options, selected, multi=True):
            seen.setdefault(question, (options, selected))
            return list(selected)

    installwizard.run(Spy(), None)
    options, selected = seen["Protocols"]
    assert "WireGuard  (2 profiles)" in options
    assert selected == ["WireGuard  (2 profiles)"]


def test_rerun_config_wins_over_detection(wizard, monkeypatch):
    cfg = config.Config()
    cfg.providers = {"wireguard": False}
    config.save_config(cfg)
    monkeypatch.setattr(installwizard, "detect", detected(WireGuard="2 profiles"))
    assert installwizard.run(FakePrompter(), None) == 0
    assert "WireGuard" not in visible(config.load_config())
    assert "OpenVPN" in visible(config.load_config())


def test_cancel_saves_nothing(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    packages = wizard / "packages"
    packages.write_text("untouched")
    assert installwizard.run(FakePrompter(choices=[None]), packages) == 1
    assert not config.CONFIG_PATH.exists()
    assert packages.read_text() == "untouched"


def test_packages_file_lists_missing(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    asked = []

    def missing(names):
        asked.append(names)
        return ["openvpn"]

    monkeypatch.setattr(installwizard, "missing_packages", missing)
    packages = wizard / "packages"
    assert installwizard.run(FakePrompter(choices=[["OpenVPN"]]), packages) == 0
    assert packages.read_text() == "openvpn\n"
    assert asked == [["openresolv", "openvpn", "python"]]


def test_features(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    prompter = FakePrompter(choices=[["Happ"], ["IPv6 guard", "DNS leak test after connect"]])
    installwizard.run(prompter, None)
    cfg = config.load_config()
    assert cfg.killswitch_mode == "off"
    assert cfg.ipv6_guard
    assert cfg.dns_mode == "subscription"
    assert cfg.dns_autotest
    assert cfg.ip_sources["ipwhois"]["enabled"] is False
    assert prompter.questions == ["Protocols", "Features"]  # no kill switch mode question


def test_feature_preselection_from_config(wizard, monkeypatch):
    config.save_config(config.Config(killswitch_mode="happ", ipv6_guard=False, dns_autotest=True))
    monkeypatch.setattr(installwizard, "detect", detected())
    seen = {}

    class Spy(FakePrompter):
        def choose(self, question, options, selected, multi=True):
            seen[question] = selected
            return list(selected)

    installwizard.run(Spy(confirms=[True, False]), None)
    assert seen["Features"] == [
        "Kill switch",
        "DNS through the tunnel",
        "DNS leak test after connect",
        "ipwho.is",
    ]
    assert seen["Kill switch"] == ["Happ only"]
    assert config.load_config().killswitch_mode == "happ"


def test_killswitch_mode_and_lockdown(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    prompter = FakePrompter(
        confirms=[False],  # Lockdown
        choices=[["Happ"], ["Kill switch"], ["Every provider"]],
    )
    installwizard.run(prompter, None)
    cfg = config.load_config()
    assert cfg.killswitch_mode == "all"
    assert cfg.killswitch_lockdown is False


def test_api_keys_asked_on_fresh_config_only(wizard, monkeypatch):
    monkeypatch.setattr(installwizard, "detect", detected())
    installwizard.run(FakePrompter(texts=["secret-key-123"]), None)
    assert config.load_config().ip_sources["abuseipdb"]["api_key"] == "secret-key-123"
    # a re-run asks first; Enter (no) keeps the key without asking for it
    installwizard.run(FakePrompter(texts=["other"]), None)
    assert config.load_config().ip_sources["abuseipdb"]["api_key"] == "secret-key-123"


def test_tools_visible_untouched(wizard, monkeypatch):
    cfg = config.Config()
    cfg.tools_visible = {"speed_test": False}
    config.save_config(cfg)
    monkeypatch.setattr(installwizard, "detect", detected())
    installwizard.run(FakePrompter(), None)
    assert config.load_config().tools_visible == {"speed_test": False}


def test_noninteractive_run_saves_preselection(wizard, monkeypatch):
    monkeypatch.setattr(installwizard.sys, "stdin", Tty(False))
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted"))
    monkeypatch.setattr(installwizard, "detect", detected(Happ="installed"))
    assert installwizard.run(installwizard.TerminalPrompter(), wizard / "packages") == 0
    assert visible(config.load_config()) == ["Happ"]


def test_resolved_switch_question(wizard, monkeypatch, capsys):
    mismatch = installwizard.Detection(resolved_active=True, resolvconf_provider="openresolv")
    monkeypatch.setattr(installwizard, "detect", lambda: mismatch)
    monkeypatch.setattr(installwizard, "missing_packages", lambda names: names)
    packages = wizard / "packages"

    installwizard.run(FakePrompter(confirms=[True], choices=[["OpenVPN"]]), packages)
    lines = packages.read_text().split()
    assert "systemd-resolvconf" in lines
    assert lines[-1] == installwizard.RESOLV_STUB_MARK
    assert "isn't systemd-resolved's stub" not in capsys.readouterr().err

    installwizard.run(FakePrompter(confirms=[False], choices=[["OpenVPN"]]), packages)
    lines = packages.read_text().split()
    assert "systemd-resolvconf" not in lines
    assert installwizard.RESOLV_STUB_MARK not in lines
    assert "isn't systemd-resolved's stub" in capsys.readouterr().err

    class NoConfirm(FakePrompter):
        def confirm(self, question, default):
            assert "systemd-resolved" not in question
            return default

    installwizard.run(NoConfirm(choices=[["OpenVPN"]]), None)  # --configure never asks


def test_switch_mark_even_when_systemd_resolvconf_is_installed(wizard, monkeypatch):
    # a re-run after pacman -S failed past the openresolv removal must finish the job
    det = installwizard.Detection(resolved_active=True, resolvconf_provider="systemd-resolvconf")
    monkeypatch.setattr(installwizard, "detect", lambda: det)
    packages = wizard / "packages"
    installwizard.run(FakePrompter(confirms=[True], choices=[["WireGuard"]]), packages)
    assert packages.read_text().split() == [installwizard.RESOLV_STUB_MARK]


def test_found_summary_marks_hidden(wizard, monkeypatch, capsys):
    monkeypatch.setattr(installwizard, "detect", detected(WireGuard="2 profiles", Happ="installed"))
    installwizard.run(FakePrompter(choices=[["Happ"]]), None)
    err = capsys.readouterr().err
    assert "WireGuard: 2 profiles (hidden)" in err
    assert "Happ: installed\n" in err


def test_package_summary(wizard, monkeypatch, capsys):
    monkeypatch.setattr(installwizard, "detect", detected())
    monkeypatch.setattr(installwizard, "missing_packages", lambda names: ["openvpn"])
    installwizard.run(FakePrompter(choices=[["OpenVPN"]]), wizard / "packages")
    err = capsys.readouterr().err
    assert "already installed: openresolv python" in err
    assert "will install: openvpn" in err
