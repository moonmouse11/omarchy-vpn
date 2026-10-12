# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Ported to Omarchy 4: the Waybar `custom/vpn` module is now an omarchy-shell bar
  widget plugin (`omarchy-vpn`, `plugin/`), the Walker menus run in omarchy.menu
  (`omarchy-menu-select` / `omarchy-menu-input`), and the bar refreshes over the
  shell's IPC (`omarchy-shell omarchy-vpn refresh`) instead of `pkill -RTMIN+11 waybar`.
- The backend installs to `~/.local/share/omarchy-vpn/src/`, the SUPER+Shift+V
  binding goes to `~/.config/hypr/bindings.lua`.

### Removed

- Waybar/Walker support and the `waybar/` wrapper scripts — Omarchy 3 stays on
  waybar-vpn-manager.

## [0.1.0] - 2026-10-11

First release: a fork of [waybar-vpn-manager](https://github.com/moonmouse11/waybar-vpn-manager)
0.3.0 (archived), renamed ahead of the Omarchy 4 port.

[Unreleased]: https://github.com/moonmouse11/omarchy-vpn/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moonmouse11/omarchy-vpn/releases/tag/v0.1.0
