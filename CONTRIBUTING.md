# Contributing

## Branches

- **Open pull requests against `dev`, not `main`.**
- `main` holds releases only. `omarchy plugin add` and `omarchy plugin update` install whatever
  `main` points to (they can't pin a tag or commit), and the panel's *Finish/Update setup* runs
  that commit's `install.sh` with sudo. Anything merged into `main` reaches users the same day.

## Privileged code

`install.sh`, `uninstall.sh` and everything in `scripts/` (`omarchy-vpn-helper`, `happ-killswitch`,
`openvpn-dns-updown`, the sudoers rule) run as root. If your PR touches them, say so in its
description: plugins.omarchy.org approves one exact commit, and a change there needs a new
maintainer review before the listing is verified again.

Keep the sudoers rule to fixed, root-owned entry points with a fixed command surface — profile
names, never paths (see `scripts/omarchy-vpn-helper`). The marketplace scanner blocks broad
`NOPASSWD` rules.

## Before a PR

```bash
make test-docker-build   # once, or after pyproject.toml's dev deps change
make test-docker         # ruff, mypy and the tests, with no network and no host VPN state
```

`make test-docker` is the safe default on a machine with a live VPN: the tests mock every call
to `happd`, `wg-quick`, `nmcli`, … they know about, and a gap in that mocking would reach the
real system on the host. QML has no tests — check a widget change live (`make install`, which
restarts the shell).

## Releasing (maintainers)

1. Merge `dev` into `main`; bump `version` in `manifest.json` and `pyproject.toml`, update
   `CHANGELOG.md`.
2. Tag it: `git tag vX.Y.Z && git push origin main vX.Y.Z`.
3. Submit the commit through the marketplace's
   [Plugin verification](https://github.com/omacom/omarchy-plugin-marketplace/issues/new?template=verify-plugin.yml)
   form ("Verify and publish a newer upstream commit", the full 40-character SHA). The listing shows
   *Update unverified* until a maintainer approves it.
