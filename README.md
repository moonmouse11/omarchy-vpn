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
window for **WireGuard, AmneziaWG, OpenVPN, VLESS and Shadowsocks keys, Happ subscriptions** and
any VPN managed by **NetworkManager**.

> Omarchy 3 (Waybar + Walker) is served by
> [waybar-vpn-manager](https://github.com/moonmouse11/waybar-vpn-manager) (archived at v0.3.0).

## Features

- **Bar widget** — a lock icon with the active connection; a left click opens the panel, a right
  click (or **SUPER+Shift+V**) the app window.
- **Every server in one list** — Happ grouped by subscription, WireGuard, AmneziaWG, OpenVPN,
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
VLESS/Shadowsocks keys) and AmneziaWG (`amneziawg-tools`, `amneziawg-dkms`). The installer
reminds you when you pick them.

### What setup changes

- Installs only the packages your picks need (`wireguard-tools`, `openvpn`, a `resolvconf`).
- Adds three root-owned helpers to `/usr/local/bin` (`omarchy-vpn-helper`, `happ-killswitch`,
  `openvpn-dns-updown`) and a sudoers rule (`/etc/sudoers.d/vpn-manager`) that lets your user run
  exactly those, plus the IPv6 guard's `sysctl` calls, without a password. The helper refuses
  VPN configs that would run commands as root.
- Copies the app to `~/.local/share/omarchy-vpn` and adds the SUPER+Shift+V binding to
  `~/.config/hypr/bindings.lua`.
- `/etc/resolv.conf` is left alone, unless you agree to switch it back to systemd-resolved
  when the installer asks.

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
