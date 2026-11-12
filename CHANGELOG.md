# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Serialize key imports, deletion and legacy UID assignment so parallel operations do not
  silently discard imported credentials; keep the existing private store format.
- Report malformed Windscribe locations as errors instead of crashing; unknown connected
  labels cannot confirm a target or bypass disconnect-before-fallback handling.
- Keep server lists populated when the panel and app window are simultaneously visible;
  synchronize their applied filter text while keeping typing local until Enter.
- Settings, setup, kill-switch preferences and remembered speed-test URLs merge only
  their edits under a shared file lock, preserving unrelated concurrent configuration changes.
- Windscribe disconnect waits for confirmed teardown; provider switching and Disconnect All
  find live tunnels even when fetching a provider's server catalogue fails.
- Subscription refresh rejects mixed invalid entries and responses over 16 MiB without
  replacing the last good cache. Removed unused duplicate subscription helpers.
- Backend IPC applies a shared monotonic deadline across each request's socket operations,
  so a peer sending one byte at a time cannot extend the wait indefinitely. Provider
  handlers themselves are not forcibly interrupted.

### Tests

- A disposable Omarchy VM gate verifies actual filter input/results in the panel and
  window, simultaneous visibility and shared filter updates, empty hidden-list models,
  zero vendor actions and absence of QML runtime errors.

## [0.4.0] - Unreleased

### Upgrade notes

Run **Update setup** in the panel (or `make install`) after updating. This release changes the
root-owned helpers, trusted Python modules and backend layout; updating the plugin clone alone
does not update those installed copies. Maintainer verification must cover the new release SHA.

Existing profile, key, subscription and quick-connect files are retained. Endpoint bootstrap uses
your configured IPv4 DNS upstreams and `/etc/hosts`, without a public fallback or automatic DNS
settings changes. Strict DNS-over-TLS and unsupported local DNS proxies fail explicitly rather
than silently falling back to plaintext. OpenVPN option names must be plain; quoted/escaped
option names are rejected before native startup. Quoted hostname arguments remain supported.

### Added

- **INCY Desktop subscriptions** alongside Happ: subscription groups, refresh, connect/disconnect,
  xray-based ping and installer detection. Tested with INCY Desktop 3.9.0 and bundled Ferrum
  26.10.13; the INCY app and plugin cannot own a tunnel at the same time.
- **Copy exit IP** by clicking the cached public IP in the connection summary.
- **Profile deletion** for VLESS/Shadowsocks keys, with quick-connect cleanup, plus OpenVPN
  autostart management through `openvpn-client@`.
- **Orphan WireGuard/AmneziaWG tunnels** remain visible and can be disconnected when their
  profile file is missing.
- Isolated native DNS/nft and pinned INCY library tests for bootstrap, routing, tunnel traffic,
  cancellation, process cleanup and proxy/direct permission separation.

### Security

- Replace the broad connect-time DNS exception with authenticated, uplink-bound bootstrap
  sockets. Firewall permission requires the dedicated mark, a configured upstream and TCP/UDP
  port 53; ordinary application and shared systemd-resolved DNS get no exception.
- WireGuard, AmneziaWG and OpenVPN use one endpoint-address snapshot for both the firewall and
  private numeric runtime profiles, avoiding a second native hostname lookup.
- INCY native library code runs as the desktop user. Fixed root-owned brokers provide narrowly
  validated TUN/socket operations instead of executing a user-writable runner as root.
- SaveConfig recovery refuses to overwrite replacement credentials/settings and retains private
  recovery data on conflict. Profile deletion/import serialize with native operations; deleting
  an inactive profile discards obsolete runtime state before the name is reused.

### Fixed

- Protection caches distinguish providers and subscriptions even when server names match;
  old name-only records must be checked again before earning Protected.
- Happ/INCY subscriptions with identical display names keep separate connect, favourite and
  ping ownership.
- Bootstrap firewall scope follows resolver changes after the previous tunnel is stopped;
  a failed refresh aborts before endpoint lookup or native startup.
- OpenVPN detects and stops standard systemd client units without helper PID files. Managed
  autostart units use the desktop connection's PID/DNS lifecycle and optional IPv6 boot guard.
- Uninstall removes managed boot/service drop-ins before deleting the helper and stops if
  that cleanup fails.
- DNS probe timeouts and cancellation no longer wait for stuck libc lookups or delay process
  exit.
- OpenVPN active detection and disconnect work with a freshly created PID directory: only PID
  metadata is readable by the desktop user; runtime profiles and credentials stay private. A
  rejected native start removes its empty PID placeholder so the next attempt can succeed.
- WireGuard/AmneziaWG SaveConfig preserves IPv6 interface addresses and peer AllowedIPs removed
  for guarded startup, including interrupted-save recovery, without discarding native IPv4/port
  changes or replacing newer source credentials. This preserves configuration; it does not add
  IPv6 tunnelling.
- Bootstrap tries another configured DNS upstream after server errors such as SERVFAIL/REFUSED,
  within the same deadline; NXDOMAIN remains terminal.
- Failed endpoint bootstrap or final firewall setup reconciles the IPv6 guard after teardown,
  without opening the cancellation/handover gap.
- DNS protection no longer trusts a resolver solely by its brand or ASN. Missing/stale evidence
  cannot earn Protected; configured LAN resolvers are warnings, not proof of a packet-path leak.
- AmneziaWG detection handles userspace implementations and avoids assigning same-named
  interfaces to the wrong kernel provider.

### Changed

- Faster status polling through provider-specific active-connection probes and an early status
  entry point that avoids loading the full CLI facade.
- Backend code is organized into app, subscription, ping and provider modules while retaining
  compatible facade patch targets.

### Known limitations

- INCY configurations containing Shadowsocks temporarily disable TUN sniffing to avoid a
  reproduced HTTP/TLS stall in the external-TUN-FD path. Domain rules requiring sniffed names may
  not match; IP-based rules and kill-switch separation are unchanged. VLESS-only configurations
  retain sniffing. The underlying cause is still under investigation.
- Tunnels remain IPv4-only; the optional IPv6 guard disables IPv6 rather than tunnelling it.
- NetworkManager VPNs remain outside the plugin-managed kill switch.

## [0.3.2] - 2026-10-28

Run **Update setup** in the panel (or `make install`) after updating: the helpers and the
sudoers rule are copies.

### Security

- Setup installs the root helpers from a copy read before the password prompt and checks each
  one's hash as root: a helper swapped in the plugin folder during the prompt no longer gets
  installed. The sudoers rule names your numeric user id instead of your user name.

## [0.3.1] - 2026-10-27

### Fixed

- A protocol or subscription with one server says "1 server", not "1 servers".
- The marketplace listing describes the window and panel, not the removed menu.

## [0.3.0] - 2026-10-27

Run **Update setup** in the panel (or `make install`) after updating: the sudoers rule, the root
helpers and the backend are copies.

### Added

- Install from the Omarchy plugin marketplace: `omarchy plugin add` downloads the plugin, the
  panel's **Finish setup** runs the installer in a terminal, **Update setup** after an update.
- An install wizard: protocols and features are asked before any password (preselected from
  what's already set up), and only the packages your picks need are installed.
- ⚙ Settings → "IPv6 guard" (on by default): IPv6 off while a VPN is up and at boot. Off, IPv6
  stays on under the tunnel and the IPv6 badge says why.

### Security

- IPv6 no longer leaks at boot with WireGuard/AmneziaWG autostart: those tunnels come up before
  login, and IPv6 used to go off only once the bar started. A systemd drop-in now turns it off
  right before the tunnel. `make install` adds it to profiles whose autostart is already on.
- The sudoers rule no longer gives passwordless root to anything running as the user. It used
  to allow `wg-quick` with any arguments (a config's `PostUp` runs as root), `cp`/`cat` with
  wildcards that span `..` (any file, the private keys) and `kill` of any process. Now it allows
  three fixed entry points: the new root-owned `omarchy-vpn-helper` (profile names only, never
  paths), `happ-killswitch` and the IPv6 guard's `sysctl`. Run `make install` to replace the rule.
- Importing a WireGuard config with `PreUp`/`PostUp`/`PreDown`/`PostDown` is refused — those run
  as root. An OpenVPN config is imported only when every directive is on a list of ordinary client
  directives: anything else (`up`, `route-up`, `plugin`, `dns-updown`, `providers`, `setenv`,
  `auth-user-pass FILE`, …, also written as `--up`, `"up"` or `setenv opt up`) is refused, and so
  are keys and certificates given as file paths (only inline `<ca>`… blocks: root would read the
  file), `http-proxy`/`socks-proxy` (an auth file) and `user`/`group`.
- WireGuard/AmneziaWG profile names longer than 15 characters are refused: `wg-quick` takes
  such a name for a path and read the config from the caller's current directory, as root.
- `make install` lists VPN configs already on disk that the import would refuse.
- The subscription header capture is gone: it installed a trusted local CA whose key sat in
  the shared `/tmp`. `~/.config/happ-capture/headers.json` still works as a manual override.
- IPv6 stays off while switching servers — it came back on between the old tunnel going down and
  the new one coming up — and goes off for tunnels the plugin didn't start (WireGuard autostart at
  boot, the Happ app, NetworkManager).

### Changed

- A connect is refused, with a hint, while the open Happ app holds a tunnel: both ran xray under
  the same id and knocked each other out. Either the plugin or the Happ app owns a connection.

### Fixed

- Happ connects no longer hang on a stale subscription: the server comes from the cached list
  (the fetch could take 15 s twice per click, past the connect timeout).
- Quick clicks while switching no longer answer "Already switching": a new click waits for the
  handover to the previous one and then takes over.
- A tunnel of a provider hidden in ⚙ Settings no longer shows the bar as "not connected".
- Switching servers fast could report the failure of the keeper it had just replaced (Happ,
  keys): a connect now waits for its own keeper's answer.
- The background subscription refresh logs why a subscription didn't update (once per new
  reason) — it used to fail silently, and the server list just stayed old.
- A failed Finish setup / `make install` step now says "Setup failed" — the setup terminal
  printed omarchy's green "Done!" under the error.

### Removed

- `socat` from the installed packages: nothing used it.
- The header capture and happd sniffing scripts (`sub-intercept-*`, `happd-sniff*`,
  `happd-extract-config.py`).

## [0.2.0] - 2026-10-18

Omarchy 4 port. `make install` again after updating: it rewrites the SUPER+Shift+V binding, adds the
window rules and restarts the shell so the new widget code loads.

### Added

- App window (SUPER+Shift+V, a right click on the widget, `m` in the panel): Locations next to
  Connection and Tools, with the panel's keys. Protocols show as a tree (default), tabs or a
  sidebar — ⚙ Settings → "Protocols in the VPN window".
- Bar panel: hero, protection badges (exit country, DNS, IPv6, kill switch — the lock only once
  every check passed), Tools, and every server — Happ grouped per subscription, "Auto — best
  ping", a filter that also matches flag country codes.
- Profiles in the window: "+ Import" (`i`) — a config path, the desktop file chooser, or a pasted
  VLESS/SS key (sent over stdin, never argv); right click (`a` / `x`) toggles a WireGuard/
  AmneziaWG/NetworkManager profile's autostart or deletes it.
- Checks in a card: DNS Leak Test, IP Info and Speed Test show progress and results over the
  window, or in a small "VPN Check" window when started from the panel.
- Quick connect: star servers (☆ or `s`); favourites and the last three servers become chips above
  the list, and the power switch reconnects the last server.
- Configurable bar label template (`labelFormat`, `f` cycles presets).
- Strict kill switch with Lockdown: DNS only through the tunnel, plugin-started xray marked past
  the rules, Docker/libvirt/podman (forwarded) traffic covered too (Mullvad's layout).
- Happ subscriptions fetched headless with Happ's own User-Agent and device id; panels answering
  stub "servers" (device limit, unsupported client) are filtered and say why.
- Pings measured on demand (Ping, a group's ⟳, a row's ping, `p`) through a short-lived xray per
  server — the delay through the server, also under the kill switch.

### Changed

- Ported to Omarchy 4: the Waybar `custom/vpn` module is now an omarchy-shell bar widget plugin
  (`omarchy-vpn`, `plugin/`), and the bar refreshes over the shell's IPC (`omarchy-shell
  omarchy-vpn refresh`) instead of `pkill -RTMIN+11 waybar`.
- The backend installs to `~/.local/share/omarchy-vpn/src/`, the SUPER+Shift+V binding goes to
  `~/.config/hypr/bindings.lua`.
- One switch at a time, and the newest one wins: a new connect cancels a stuck one instead of
  queueing behind it.

### Fixed

- Hostname servers under the kill switch (xray's own lookup of its server).
- `make uninstall` turns the kill switch off and removes `happ-killswitch` and
  `openvpn-dns-updown` — with Lockdown on, the rules used to block all traffic until a reboot.
- Typing `j`/`k`/`h`/`l` in the panel's filter no longer moves the cursor.

### Removed

- The omarchy.menu main menu and its submenus (`--menu`, `--dns-leak-test`): everything moved into
  the app window and the panel. omarchy-menu-select is no longer needed.
- Waybar/Walker support and the `waybar/` wrapper scripts — Omarchy 3 stays on
  waybar-vpn-manager.

## [0.1.0] - 2026-10-11

First release: a fork of [waybar-vpn-manager](https://github.com/moonmouse11/waybar-vpn-manager)
0.3.0 (archived), renamed ahead of the Omarchy 4 port.

[Unreleased]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.3.2...HEAD
[0.4.0]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.3.2...release/0.4.0
[0.3.2]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/moonmouse11/omarchy-vpn/releases/tag/v0.1.0
