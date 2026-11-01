# omarchy-vpn

[![Tests](https://github.com/moonmouse11/omarchy-vpn/actions/workflows/python.yml/badge.svg?branch=main)](https://github.com/moonmouse11/omarchy-vpn/actions/workflows/python.yml)
[![xray compatibility](https://github.com/moonmouse11/omarchy-vpn/actions/workflows/xray-compat.yml/badge.svg?branch=main)](https://github.com/moonmouse11/omarchy-vpn/actions/workflows/xray-compat.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=moonmouse11_omarchy-vpn&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=moonmouse11_omarchy-vpn)
[![Release](https://img.shields.io/github/v/release/moonmouse11/omarchy-vpn)](https://github.com/moonmouse11/omarchy-vpn/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

![Omarchy 4](https://img.shields.io/badge/Omarchy-4-1e1e2e)
![Arch Linux](https://img.shields.io/badge/Arch_Linux-1793D1?logo=archlinux&logoColor=white)
![Hyprland](https://img.shields.io/badge/Hyprland-58E1FF?logo=hyprland&logoColor=black)
![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)
![QML / Quickshell](https://img.shields.io/badge/QML-Quickshell-41CD52?logo=qt&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=white)
![nftables](https://img.shields.io/badge/nftables-kill_switch-555)

A VPN manager for the [Omarchy](https://omarchy.org/) 4 shell: a bar widget, a panel and an app
window for **WireGuard, AmneziaWG, OpenVPN, VLESS and Shadowsocks keys, Happ/INCY subscriptions** and
any VPN managed by **NetworkManager**.

> Omarchy 3 (Waybar + Walker) is served by
> [waybar-vpn-manager](https://github.com/moonmouse11/waybar-vpn-manager) (archived at v0.3.0).

## Features

- **Bar widget** — a lock icon with the active connection; a left click opens the panel, a right
  click (or **SUPER+Shift+V**) the app window.
- **Every server in one list** — Happ/INCY grouped by subscription, WireGuard, AmneziaWG, OpenVPN,
  imported keys and NetworkManager VPNs. Filter with `/` (by name, protocol or country code),
  connect with a click or Enter, star favourites for quick connect.
- **Happ without the Happ window** — servers come straight from your subscriptions and connect
  in the background; the Happ app keeps working alongside.
- **Protection checks** — the panel says *Protected* only once the exit country, DNS and IPv6
  all check out; otherwise *Unverified* or *At risk*, with the reason.
- **Kill switch** — no tunnel, no internet (see [Kill switch](#kill-switch)).
- **IPv6 leak guard** — IPv6 is off while a VPN is up (none of these tunnels carry it), also at
  boot for WireGuard autostart.
- **DNS through the tunnel** for Happ and keys.
- **Tools** — DNS leak test, IP info, speed test, ping through each server, refresh
  subscriptions, clear caches.
- **Import and manage profiles** — a config file or a pasted `vless://` / `ss://` key; toggle
  autostart or delete WireGuard/AmneziaWG/NetworkManager profiles.

## Install

```bash
omarchy plugin add https://github.com/moonmouse11/omarchy-vpn --enable
```

`omarchy plugin add` only downloads the plugin. The widget then shows **Setup needed**: open its
panel and press **Finish setup**. A terminal opens, asks which protocols and features you want,
then your sudo password once, and installs what's missing. You can review the script first:
`~/.config/omarchy/plugins/omarchy-vpn/install.sh` (or run it yourself).

After `omarchy plugin update omarchy-vpn` the panel shows **Update setup** — press it once more.

From a checkout instead: `git clone https://github.com/moonmouse11/omarchy-vpn && cd omarchy-vpn && make install`.

**You install yourself, if you want them:** Happ (AUR: `happ-desktop-bin` — also needed for
VLESS/Shadowsocks keys), INCY Desktop (see [INCY setup](#incy-setup)), and AmneziaWG
(AUR: `amneziawg-tools` plus `amneziawg-dkms` and
`linux-headers`, or prebuilt `amneziawg-linux` for the stock kernel). The installer
reminds you when you pick them.

### What setup changes

- Installs only the packages your picks need (`wireguard-tools`, `openvpn`, a `resolvconf`).
- Adds root-owned helpers to `/usr/local/bin` (`omarchy-vpn-helper`, `happ-killswitch`,
  `openvpn-dns-updown`, `omarchy-vpn-incy-network`) and the INCY helper's isolated Python package
  to `/usr/local/lib/omarchy-vpn`. The sudoers rule (`/etc/sudoers.d/vpn-manager`) grants access
  only to `omarchy-vpn-helper`, `happ-killswitch` and the IPv6 guard's fixed `sysctl` calls.
  OpenVPN invokes its DNS helper; the main helper invokes INCY's fixed network entry.
  Privileged helper sources are copied before the sudo prompt and re-hashed after installation.
  The main helper refuses VPN configs that would run commands as root.
- Copies the app to `~/.local/share/omarchy-vpn` and adds the SUPER+Shift+V binding to
  `~/.config/hypr/bindings.lua`.
- `/etc/resolv.conf` is left alone, unless you agree to switch it back to systemd-resolved
  when the installer asks.

### INCY Shadowsocks compatibility

INCY configurations containing Shadowsocks temporarily run with TUN sniffing disabled,
including mixed/balancer configurations. This avoids a reproduced stall in our external-TUN-FD
path with bundled Ferrum 26.10.13. Domain rules that need sniffed names may not match;
IP-based rules and the kill switch are unchanged. VLESS-only configurations keep sniffing.
This is a compatibility workaround, not a confirmed application-wide Ferrum bug.

## Usage

| Where | How |
|---|---|
| Panel | left click on the widget |
| App window | SUPER+Shift+V, a right click on the widget, or `m` in the panel |
| Connect / disconnect | click a server, or move with `j`/`k` and press Enter |
| Filter | `/` (Esc leaves it) |
| Ping | the Ping button, ⟳ on a group, a click on a server's ping, or `p` |
| Favourite | ☆ on a row, or `s` |
| Import a profile | **+ Import** on a protocol in the window, or `i` |
| Autostart / delete | right click on a server in the window, or `a` / `x` |
| DNS leak test | the DNS badge (when it isn't green), or `d` |

### Settings

The window's **Settings** button opens every option in a small terminal: Space changes one,
`s` saves, `q` quits. Re-running the installer asks the setup questions again.

The bar label can be changed with `omarchy bar set omarchy-vpn labelFormat '{server} · {ping}'`
(or `f` in the panel cycles presets). Useful placeholders: `{label}`, `{server}`, `{provider}`,
`{ping}`, `{exit_country}`, `{exit_flag}`, `{rate}`, `{state}`.
`omarchy bar set omarchy-vpn showLabel false` shows the icon only.

## Kill switch

When on, nothing leaves the computer except through the VPN — local network devices stay
reachable. Pick a mode in Settings:

- **off** — only the window's Kill switch button turns it on;
- **happ** — on automatically while Happ is connected;
- **all** — on automatically for every connection.

**Lockdown** (on by default) keeps blocking even when no VPN is up, so a dropped tunnel never
falls back to your real connection. If you're ever locked out:

```bash
sudo /usr/local/bin/happ-killswitch off
```

The rules don't survive a reboot.

## Happ setup

Usually nothing to do: subscriptions are fetched the way the Happ app fetches them, as the same
device, so no extra device slot is used.

If a provider still refuses (device limit, unsupported client), the server list shows
`<provider> · ⚠ <its message>` — free a device slot with your provider. If a provider needs
other request headers, put them in `~/.config/happ-capture/headers.json` as one JSON object
(`{"User-Agent": "…", "X-Hwid": "…"}`) and `chmod 600` it; they replace the default ones.

## INCY setup

1. Install **INCY Desktop** yourself: AUR `incy-bin`, or the official Arch `.pkg.tar.zst`
   from [INCY's releases](https://github.com/INCY-DEV/incy-platforms). The plugin installer
   does not download or install INCY. The tested package is Desktop **3.9.0**, bundled
   **Ferrum 26.10.13 (0da8c683)**; other versions are not guaranteed compatible.
2. Open INCY and add your subscription URLs/QR codes there. The plugin reads its
   `~/.local/share/incy/incy.db` and keeps separate subscription caches; it does not import
   subscriptions into the app or replace its database.
3. Disconnect any tunnel in the INCY app before connecting from the plugin. Enable INCY
   in the plugin's Settings if hidden, then select a server in Locations. Refresh All
   updates subscription caches; Ping measures through a separate short-lived core.

The default installation is `/opt/incy`. Both `lib/app/resources/bin/libincycore.so` and
its sibling `libxray_ffi.so` are required; a standalone `xray` binary is not used.
Discovery also checks `incy` in PATH and the user desktop entry. For a custom installation,
set `OMARCHY_VPN_INCY_ROOT` to the directory containing `lib/` and `bin/` in the environment
inherited by the shell/plugin, not just in an unrelated terminal.

**One owner at a time.** The app's tunnel is `tun_incy`; the plugin's is `incy-xray`.
The plugin refuses connect/disconnect actions while the app owns a tunnel: disconnect in
INCY first. Closing its window is not a substitute for disconnecting.

**Privilege boundary.** `make install` installs the fixed root-owned network helper and
its isolated Python package. The helper accepts only a mode and random session token;
it creates the fixed TUN/routes and binds outgoing sockets to the uplink. It never loads
INCY libraries, subscription configuration or user code. The library worker runs as the
user with no root UID or capabilities. Connect and Ping both use this separation.
The kill switch accepts broker mark `0x6b74` only together with generated proxy priority
`6`; subscription-direct traffic does not gain a blanket bypass.

**Upgrading from the old `incy-run` implementation:** disconnect the old connection,
update the plugin and run **Update setup** (or `make install` from the checkout). Updating
only the user backend is not enough: the root helpers/package must match too. The old
root execution command is removed; there is no fallback to running the core as root.
Your INCY database/subscriptions are kept. If startup fails, the plugin checks basic config
structure before launching the broker; full protocol/config validation happens in the
unprivileged worker, with its error returned to the caller.

See [INCY Shadowsocks compatibility](#incy-shadowsocks-compatibility) for the temporary
TUN sniffing limitation, including its effect on domain-based routing.

### Native test pinning

The optional native suite verifies both library hashes against tracked
`tests/incy-artifacts.sha256` **before network setup or loading native code**:

```bash
make test-docker-build
make test-incy-docker INCY_TEST_ROOT=/path/to/extracted/opt/incy
```

All network changes stay inside the disposable container. An absent or different library
fails the test; these hashes are **not** an install/runtime allowlist for users.
To test a new release, authenticate its official package and record its provenance, update
both library hashes and package/version comments in the manifest, then run the native
suite and regular `make test-docker`. Retain the update only with successful compatibility
results; changing a hash alone is not evidence of compatibility. The standalone
`tests/incy_ferrum_check.py` uses the same pin before its no-TUN control checks.

## Privacy

Besides your VPN servers and subscriptions, the plugin talks to: `ipwho.is` and `ip-api.com`
(your exit IP and its country), `bash.ws` (DNS leak test), `www.gstatic.com` (ping),
Cloudflare/OVH/Hetzner speed test servers (only when you run one). AbuseIPDB and IPQualityScore
only if you add an API key. These lookups send only the IP address being checked, and go
through the VPN while one is up.

## Troubleshooting

- Log: `~/.local/state/vpn-manager/vpn-manager.log`
- Errors (a config the installed xray rejects, a tunnel that died) show as notifications with
  the reason.
- Settings: `~/.config/vpn-manager/`; caches: `~/.cache/vpn-manager/` (the Clear caches tool
  empties them).

## Uninstall

```bash
~/.config/omarchy/plugins/omarchy-vpn/uninstall.sh
omarchy plugin remove omarchy-vpn
```

Run `uninstall.sh` first: it turns the kill switch off and removes the helpers, the sudoers rule,
the app and the key binding. Removing the plugin alone would leave them behind. Your settings,
keys and favourites in `~/.config/vpn-manager` are kept. From a checkout: `make uninstall`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests go to `dev`.

## License

MIT — see [LICENSE](LICENSE). `src/dnsleak.py` reimplements the protocol of
[macvk/dnsleaktest](https://github.com/macvk/dnsleaktest) (MIT).
