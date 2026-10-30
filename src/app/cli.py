"""argparse entrypoint."""

import argparse
import json
import os
import sys

import happmeta
import ipinfo
import logutil
import quickconnect
import reputation
from app.checks import CHECK_TITLES, run_check, run_dns_autotest
from app.helpers import _collect_ping_targets, notify, refresh_bar
from app.patchables import patched as _patched
from app.ping import _ping_scope_from_args, ping_now
from app.servers import (
    _report,
    panel_connect,
    panel_disconnect,
    server_list,
    subscription_report,
)
from app.status import get_status
from app.switch import disconnect_all, sync_ipv6_boot
from app.tools import (
    TOOLS,
    run_import,
    run_profile_action,
    run_settings_window,
    run_tool,
)
from providers.base import (
    ActionResult,
)
from providers.happ import run_keeper as run_happ_keeper
from providers.keys import run_keeper as run_keys_keeper

# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Print JSON status for the bar widget")
    group.add_argument(
        "--disconnect-all", action="store_true", help="Disconnect every VPN (the panel's switch)"
    )
    group.add_argument(
        "--servers", action="store_true", help="Print the panel's server list as JSON"
    )
    group.add_argument(
        "--connect",
        nargs="+",
        metavar="PROVIDER NAME [SUBSCRIPTION_ID]",
        help="Connect a server (the panel's server list)",
    )
    group.add_argument(
        "--disconnect", nargs=2, metavar=("PROVIDER", "NAME"), help="Disconnect a connection"
    )
    group.add_argument(
        "--tool",
        choices=[*(key for key, _label, _fn in TOOLS), "killswitch"],
        help="Run one tool (the app window's Tools buttons; killswitch toggles it)",
    )
    group.add_argument(
        "--ipv6-boot-sync",
        action="store_true",
        help="Drop-ins turning IPv6 off before autostarted tunnels (make install)",
    )
    group.add_argument(
        "--favourite",
        nargs="+",
        metavar="PROVIDER NAME [SUBSCRIPTION_ID]",
        help="Star or unstar a server (QUICK CONNECT)",
    )
    group.add_argument(
        "--import",
        dest="import_",
        nargs="+",
        metavar="PROVIDER [PATH|-]",
        help="Import a config (no PATH: file chooser; -: a key or path on stdin)",
    )
    group.add_argument(
        "--profile",
        nargs=3,
        metavar=("autostart|delete", "PROVIDER", "NAME"),
        help="Toggle a profile's autostart or delete it (a server row's right click)",
    )
    group.add_argument(
        "--check",
        nargs="+",
        metavar="dns|ip|speed [TARGET]",
        help="Run a check for the app window's card (JSON lines); speed: all|NAME|URL",
    )
    group.add_argument(
        "--dns-autotest",
        action="store_true",
        help="Silent DNS leak test after a connect (internal, config dns_autotest)",
    )
    group.add_argument(
        "--update-ip",
        metavar="CONN_NAME",
        help="Refresh exit-IP cache in the background (internal)",
    )
    group.add_argument(
        "--happ-keeper",
        nargs="*",
        metavar="SERVER [SUBSCRIPTION_ID]",
        help="Hold the happd session that owns the xray process (internal)",
    )
    group.add_argument(
        "--keys-keeper",
        nargs=2,
        metavar=("KIND", "SERVER_ID"),
        help="Hold the happd session that owns a key xray process (internal)",
    )
    group.add_argument(
        "--ping-now",
        nargs="*",
        metavar="group ID | server PROVIDER NAME [SUB_ID]",
        help="Measure ping now: every server, one panel group, or one server (the panel)",
    )
    group.add_argument(
        "--update-subs",
        action="store_true",
        help="Refresh Happ subscription caches in the background (internal)",
    )
    group.add_argument(
        "--update-subs-force",
        action="store_true",
        help="Like --update-subs but bypassing the SUB_MAX_AGE cache gate (Refresh All)",
    )
    group.add_argument(
        "--update-reputation",
        action="store_true",
        help="Refresh server IP-reputation cache in the background (internal)",
    )
    group.add_argument(
        "--settings",
        action="store_true",
        help="Settings list in this terminal (what 🛠 Tools → ⚙ Settings opens)",
    )
    group.add_argument(
        "--configure",
        action="store_true",
        help="Interactive setup wizard: protocols, features, IP sources/keys",
    )
    group.add_argument(
        "--install-wizard",
        action="store_true",
        help="install.sh: the setup wizard, then the packages still missing on fd 3",
    )
    args = parser.parse_args()
    if args.keys_keeper is not None and args.keys_keeper[0] not in ("ss", "vless"):
        kind = args.keys_keeper[0]
        parser.error(f"argument --keys-keeper: invalid KIND {kind!r} (choose from 'ss', 'vless')")

    if args.status:
        print(json.dumps(get_status()))
    elif args.servers:
        print(json.dumps(server_list(), ensure_ascii=False))
    elif args.connect is not None:
        if len(args.connect) not in (2, 3):
            parser.error("--connect takes PROVIDER NAME [SUBSCRIPTION_ID]")
        _report(_patched("panel_connect", panel_connect)(*args.connect))
    elif args.disconnect is not None:
        _report(_patched("panel_disconnect", panel_disconnect)(*args.disconnect))
    elif args.disconnect_all:
        result = _patched("disconnect_all", disconnect_all)()
        notify("VPN", result.message, urgent=not result.success)
        refresh_bar()
    elif args.tool:
        _report(_patched("run_tool", run_tool)(args.tool))
    elif args.ipv6_boot_sync:
        boot = sync_ipv6_boot()
        print(boot.message or "IPv6 at boot: in sync")
        sys.exit(0 if boot.success else 1)
    elif args.favourite is not None:
        if len(args.favourite) not in (2, 3):
            parser.error("--favourite takes PROVIDER NAME [SUBSCRIPTION_ID]")
        if args.favourite[0] == "Happ" and len(args.favourite) != 3:
            # a Happ server is (subscription, name): without it no row ever matches
            parser.error("--favourite Happ takes NAME SUBSCRIPTION_ID")
        try:
            quickconnect.toggle_favourite(*args.favourite)
            result = ActionResult(True, "")
        except OSError as e:
            result = ActionResult(False, f"Favourite not saved: {e}")
        _report(result)  # the widget reloads the list: the star and the chips
    elif args.import_ is not None:
        if len(args.import_) not in (1, 2):
            parser.error("--import takes PROVIDER [PATH|-]")
        _report(_patched("run_import", run_import)(*args.import_))
    elif args.profile is not None:
        if args.profile[0] not in ("autostart", "delete"):
            parser.error("--profile takes autostart|delete PROVIDER NAME")
        _report(_patched("run_profile_action", run_profile_action)(*args.profile))
    elif args.check is not None:
        if args.check[0] not in CHECK_TITLES or len(args.check) > 2:
            parser.error("--check takes dns|ip|speed [TARGET]")
        _report(_patched("run_check", run_check)(*args.check))
    elif args.dns_autotest:
        run_dns_autotest()
    elif args.update_ip:
        ipinfo.update(args.update_ip)
    elif args.ping_now is not None:
        scope = _ping_scope_from_args(args.ping_now)
        if scope is None:
            print("--ping-now: group ID | server PROVIDER NAME [SUB_ID]", file=sys.stderr)
            sys.exit(2)
        if (note := ping_now(scope)) is not None:
            notify(*note)
    elif args.update_reputation:
        reputation.write_reputations(_collect_ping_targets())
    elif args.update_subs:
        # unattended (every minute while fetches fail): no bubble, one log line per new reason
        before = happmeta.last_subs_failures()
        for name, why in happmeta.update_subscriptions().items():
            if before.get(name) != why:
                logutil.log(f"subscription {name} not updated: {why}")
    elif args.update_subs_force:
        # a manual refresh (menu or Refresh All) runs in the background:
        # report every provider — a silent failure looked like success
        failed = happmeta.update_subscriptions(force=True)
        notify(*_patched("subscription_report", subscription_report)(failed))
        _patched("refresh_bar", refresh_bar)()
    elif args.happ_keeper is not None:
        run_happ_keeper(*args.happ_keeper[:2])
    elif args.keys_keeper is not None:
        run_keys_keeper(*args.keys_keeper)
    elif args.settings:
        run_settings_window()
    elif args.configure or args.install_wizard:
        import installwizard  # noqa: PLC0415 — install-time only: not on the 3 s --status path

        out = None
        if args.install_wizard:
            # only install.sh's fd 3: write_text would truncate any other file behind it
            try:
                if os.environ.get("OMARCHY_VPN_WIZARD_FD") != "3":
                    raise OSError
                os.fstat(3)
            except OSError:
                # before any question: config.json stays untouched
                sys.exit("--install-wizard writes to fd 3: run install.sh (3>FILE)")
            out = installwizard.WIZARD_OUT
        sys.exit(installwizard.run(installwizard.TerminalPrompter(), out))


if __name__ == "__main__":
    main()
