"""install.sh's questions: detect what's on the machine (no root, no network),
ask protocols/features with that preselected, list the packages still missing.

`vpn_manager.py --install-wizard 3>FILE` runs it before install.sh's first sudo
(as `python3 -B`: nothing may be written under the plugin dir, see CLAUDE.md);
`--configure` asks the same questions without the package list.
"""

import contextlib
import getpass
import json
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import config
import happmeta
import ipsources
from config import Config
from providers import ALL_PROVIDERS
from providers.keys import STORE
from providers.openvpn import OVPN_DIR
from providers.wireguard import AMNEZIA_DIR, WG_DIR

PROTOCOLS = [p.name for p in ALL_PROVIDERS]
# wg-quick, awg-quick and openvpn-dns-updown set DNS through `resolvconf`
RESOLVCONF_USERS = ("WireGuard", "AmneziaWG", "OpenVPN")
XRAY_USERS = ("Happ", "VLESS", "Shadowsocks")  # keys run on Happ's xray

AWG_DIR = AMNEZIA_DIR
HAPPD = Path("/opt/happ/bin/happd")  # what the plugin talks to, not just the app
INCY_BIN = Path("/opt/incy/bin/incy")
SUB_CACHE_DIR = happmeta.SUB_CACHE_DIR
KEYS_FILE = STORE
RESOLV_CONF = Path("/etc/resolv.conf")
RESOLVED_STUB = Path("/run/systemd/resolve/stub-resolv.conf")
# last line of the packages file after a yes to the switch: install.sh removes
# openresolv and links resolv.conf to the stub (never a package name)
RESOLV_STUB_MARK = ":resolv-stub"
# --install-wizard's package list: install.sh opens fd 3 on its mktemp file —
# never a path from argv (written while install.sh is about to run sudo)
WIZARD_OUT = Path("/dev/fd/3")


@dataclass
class Detection:
    notes: dict[str, str] = field(default_factory=dict)  # protocol → "3 profiles", found ones only
    resolved_active: bool = False
    resolvconf_provider: str = ""  # "openresolv" | "systemd-resolvconf" | ""
    resolv_stub: bool = False  # /etc/resolv.conf is systemd-resolved's stub


def _run(cmd: list[str], ok_codes: tuple[int, ...] = (0,)) -> str:
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
    except OSError, subprocess.SubprocessError:
        return ""
    return proc.stdout if proc.returncode in ok_codes else ""


def _count(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _files(directory: Path, *patterns: str) -> int:
    try:
        return sum(1 for pattern in patterns for _ in directory.glob(pattern))
    except OSError:  # root 700 before the first install
        return 0


def _wg_like(directory: Path, binary: str) -> str:
    if n := _files(directory, "*.conf"):
        return _count(n, "profile")
    units = _run(["systemctl", "list-unit-files", "--state=enabled", f"{binary}@*", "--no-legend"])
    if n := len(units.splitlines()):
        return _count(n, "autostart")
    return "installed" if shutil.which(binary) else ""


def _openvpn() -> str:
    if n := _files(OVPN_DIR, "*.conf", "*.ovpn"):
        return _count(n, "profile")
    return "installed" if shutil.which("openvpn") else ""


def _happ() -> str:
    if not HAPPD.is_file():
        return ""
    n = _files(SUB_CACHE_DIR, "subscription-*.json")
    return _count(n, "subscription") if n else "installed"


def _incy() -> str:
    if not INCY_BIN.is_file():
        return ""
    db = Path.home() / ".local/share/incy/incy.db"
    if not db.is_file():
        return "installed"
    try:
        import sqlite3

        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        try:
            (n,) = conn.execute("SELECT COUNT(*) FROM subscriptions").fetchone()
        finally:
            conn.close()
    except OSError, sqlite3.Error:
        return "installed"
    return _count(int(n), "subscription") if n else "installed"


def _keys(kind: str) -> str:
    try:
        records = json.loads(KEYS_FILE.read_text())
    except OSError, json.JSONDecodeError:
        return ""
    n = sum(1 for r in records if isinstance(r, dict) and r.get("kind") == kind)
    return _count(n, "key") if n else ""


def _networkmanager() -> str:
    types = _run(["nmcli", "-t", "-f", "TYPE", "connection"]).split()
    n = sum(1 for t in types if t in ("vpn", "wireguard"))
    return _count(n, "connection") if n else ""


# looked up at call time: tests redirect the module-level paths
_PROBES: dict[str, Callable[[], str]] = {
    "WireGuard": lambda: _wg_like(WG_DIR, "wg-quick"),
    "AmneziaWG": lambda: _wg_like(AWG_DIR, "awg-quick"),
    "VLESS": lambda: _keys("vless"),
    "Shadowsocks": lambda: _keys("ss"),
    "OpenVPN": _openvpn,
    "NetworkManager": _networkmanager,
    "Happ": _happ,
    "INCY": _incy,
}


def detect() -> Detection:
    det = Detection()
    for name in PROTOCOLS:
        try:
            note = _PROBES[name]()
        except Exception:  # noqa: BLE001, S112 — a broken probe means "not found" and never a failed install
            continue
        if note:
            det.notes[name] = note
    det.resolved_active = _run(["systemctl", "is-active", "systemd-resolved"]).strip() == "active"
    det.resolvconf_provider = _run(["pacman", "-Qq", "resolvconf"]).strip()
    with contextlib.suppress(OSError):
        det.resolv_stub = RESOLV_CONF.resolve(strict=True) == RESOLVED_STUB.resolve()
    return det


def wanted_packages(cfg: Config, det: Detection, switch_resolvconf: bool = False) -> list[str]:
    names = {"python"}
    if cfg.provider_visible("WireGuard"):
        names.add("wireguard-tools")
    if cfg.provider_visible("OpenVPN"):
        names.add("openvpn")
    if any(cfg.provider_visible(p) for p in RESOLVCONF_USERS):
        if switch_resolvconf:
            names.add("systemd-resolvconf")
        elif not det.resolvconf_provider:
            names.add("systemd-resolvconf" if det.resolved_active else "openresolv")
    if cfg.killswitch_mode != "off":
        names.add("nftables")
    return sorted(names)


def missing_packages(names: list[str]) -> list[str]:
    if not names:
        return []
    # prints the unsatisfied ones (Provides count), exit 127 when there are any
    return _run(["pacman", "-T", *names], ok_codes=(0, 127)).split()


def resolved_mismatch(cfg: Config, det: Detection) -> bool:
    """systemd-resolved runs but resolv.conf isn't its stub (an older install.sh
    replaced it with an openresolv file): DNS set through resolvectl is unused."""
    return (
        any(cfg.provider_visible(p) for p in RESOLVCONF_USERS)
        and det.resolved_active
        and not det.resolv_stub
    )


def hints(cfg: Config, det: Detection, switched: bool = False) -> list[str]:
    lines = []
    if cfg.provider_visible("AmneziaWG") and not shutil.which("awg-quick"):
        lines.append(
            "AmneziaWG: install from AUR — amneziawg-tools, amneziawg-dkms "
            "(and linux-headers), or amneziawg-linux for stock kernel"
        )
    if any(cfg.provider_visible(p) for p in XRAY_USERS) and not HAPPD.is_file():
        lines.append(
            "Happ isn't installed (AUR: happ-desktop-bin) — Happ and VLESS/Shadowsocks keys need it"
        )
    if resolved_mismatch(cfg, det) and not switched:
        lines.append(
            "DNS: /etc/resolv.conf isn't systemd-resolved's stub — "
            "DNS pushed by OpenVPN isn't used. "
            "Re-run the installer and answer yes to switch to systemd-resolved."
        )
    return lines


class Prompter(ABC):
    @abstractmethod
    def confirm(self, question: str, default: bool) -> bool: ...

    @abstractmethod
    def text(self, question: str) -> str: ...

    @abstractmethod
    def choose(
        self, question: str, options: list[str], selected: list[str], multi: bool = True
    ) -> list[str] | None:
        """The picked options (one for multi=False); None = cancelled."""


class TerminalPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        if not sys.stdin.isatty():
            return default
        suffix = "[Y/n]" if default else "[y/N]"
        # Ctrl-C / Ctrl-D propagate: run() cancels (no tty never gets here)
        answer = input(f"{question} {suffix} ").strip().lower()
        return default if not answer else answer in ("y", "yes")

    def text(self, question: str) -> str:
        if not sys.stdin.isatty():
            return ""
        return getpass.getpass(f"{question}: ").strip()

    def choose(
        self, question: str, options: list[str], selected: list[str], multi: bool = True
    ) -> list[str] | None:
        if not sys.stdin.isatty():  # scripted install: keep the preselection
            return list(selected)
        try:
            if shutil.which("gum"):
                cmd = ["gum", "choose"]
                if multi:  # gum 2.x toggles with x/Tab/Ctrl+Space, not Space
                    cmd += [
                        "--header",
                        f"{question}  (x / Tab: toggle · Enter: done)",
                        "--no-limit",
                    ]
                else:
                    cmd += ["--header", question]
                if selected:  # options carry no "," (gum's --selected separator)
                    cmd.append("--selected=" + ",".join(selected))
                # only stdout is captured: gum draws on the terminal through stderr
                proc = subprocess.run(
                    [*cmd, "--", *options], stdout=subprocess.PIPE, text=True, check=False
                )
                return proc.stdout.splitlines() if proc.returncode == 0 else None
            print(question)
            picked = [o for o in options if self.confirm(f"  {o}", o in selected)]
        except KeyboardInterrupt, EOFError:
            return None
        return picked if multi else picked[:1] or list(selected)


# ── the questions ─────────────────────────────────────────────────────────────

KILLSWITCH, IPV6_GUARD, DNS_TUNNEL, DNS_AUTOTEST = (
    "Kill switch",
    "IPv6 guard",
    "DNS through the tunnel",
    "DNS leak test after connect",
)
KILLSWITCH_MODES = {"Every provider": "all", "Happ only": "happ"}


def _source_on(cfg: Config, key: str) -> bool:
    return bool(cfg.ip_sources.get(key, {}).get("enabled", True))  # keyless default: on


def ask(prompter: Prompter, det: Detection) -> Config | None:
    """Protocols, features, kill switch mode, API keys — preselected from
    config.json, or on a fresh install from what detect() found. None = cancelled."""
    fresh = not config.CONFIG_PATH.exists()
    cfg = config.load_config()
    if not _ask_protocols(prompter, det, cfg, fresh) or not _ask_features(prompter, cfg):
        return None
    if fresh or prompter.confirm("Set IP source API keys?", False):
        _ask_api_keys(prompter, cfg)
    return cfg


def _ask_protocols(prompter: Prompter, det: Detection, cfg: Config, fresh: bool) -> bool:
    """False = cancelled."""
    # gum's --selected is comma-separated
    labels = {
        (f"{n}  ({det.notes[n].replace(',', '')})" if n in det.notes else n): n for n in PROTOCOLS
    }
    if fresh:
        preselect = [n for n in PROTOCOLS if n in det.notes] or PROTOCOLS
    else:
        preselect = [n for n in PROTOCOLS if cfg.provider_visible(n)]
    picked = prompter.choose(
        "Protocols", list(labels), [label for label, n in labels.items() if n in preselect]
    )
    if picked is None:
        return False
    chosen = {labels.get(label, label) for label in picked}
    for name in PROTOCOLS:
        cfg.providers[name.lower()] = name in chosen
    return True


def _ask_features(prompter: Prompter, cfg: Config) -> bool:
    """Features, then the kill switch mode and Lockdown. False = cancelled."""
    keyless = [s for s in ipsources.ALL_SOURCES if not s.needs_api_key]
    features = {
        KILLSWITCH: cfg.killswitch_mode != "off",
        IPV6_GUARD: cfg.ipv6_guard,
        DNS_TUNNEL: cfg.dns_mode == "tunnel",
        DNS_AUTOTEST: cfg.dns_autotest,
    } | {s.name: _source_on(cfg, s.key) for s in keyless}
    picked = prompter.choose("Features", list(features), [f for f, on in features.items() if on])
    if picked is None:
        return False
    cfg.ipv6_guard = IPV6_GUARD in picked
    cfg.dns_mode = "tunnel" if DNS_TUNNEL in picked else "subscription"
    cfg.dns_autotest = DNS_AUTOTEST in picked
    for source in keyless:
        cfg.ip_sources.setdefault(source.key, {})["enabled"] = source.name in picked

    if KILLSWITCH not in picked:
        cfg.killswitch_mode = "off"
    else:
        current = "Happ only" if cfg.killswitch_mode == "happ" else "Every provider"
        mode = prompter.choose("Kill switch", list(KILLSWITCH_MODES), [current], multi=False)
        if mode is None:
            return False
        cfg.killswitch_mode = KILLSWITCH_MODES.get(mode[0] if mode else current, "all")
        cfg.killswitch_lockdown = prompter.confirm(
            "Lockdown: keep blocking while no VPN is up?", cfg.killswitch_lockdown
        )
    return True


def _ask_api_keys(prompter: Prompter, cfg: Config) -> None:
    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            answer = prompter.text(f"{source.name} API key (Enter — keep current / skip)")
            if answer:
                cfg.ip_sources.setdefault(source.key, {})["api_key"] = answer


def run(prompter: Prompter, packages_file: Path | None) -> int:
    """detect → ask → save → (install.sh only) the packages still missing,
    one per line, into packages_file. 1 = cancelled: nothing saved or written."""
    det = detect()
    try:
        cfg = ask(prompter, det)
        if cfg is None:
            return 1
        switch = packages_file is not None and resolved_mismatch(cfg, det)
        if switch:
            switch = prompter.confirm(
                "Switch DNS to systemd-resolved? (installs systemd-resolvconf, "
                "removes openresolv, links /etc/resolv.conf to its stub)",
                False,
            )
    except KeyboardInterrupt, EOFError:  # Ctrl-C/Ctrl-D at any question = Esc in gum
        return 1
    config.save_config(cfg)  # before any sudo: an aborted password prompt keeps the answers

    for name, note in det.notes.items():
        hidden = "" if cfg.provider_visible(name) else " (hidden)"
        print(f"    found {name}: {note}{hidden}", file=sys.stderr)
    for line in hints(cfg, det, switched=switch):
        print(f"    {line}", file=sys.stderr)

    if packages_file is not None:
        wanted = wanted_packages(cfg, det, switch_resolvconf=switch)
        missing = missing_packages(wanted)
        print(
            f"    already installed: {' '.join(p for p in wanted if p not in missing) or '-'}",
            f"    will install: {' '.join(missing) or '-'}",
            sep="\n",
            file=sys.stderr,
        )
        if switch:
            missing.append(RESOLV_STUB_MARK)
        packages_file.write_text("".join(f"{name}\n" for name in missing))
    return 0
