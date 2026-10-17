install:
	@bash install.sh

# Kill switch first: Lockdown's nft rules outlive the plugin, so they go (checked gone)
# before anything is removed — a failure there leaves the install intact.
uninstall:
	[ ! -x /usr/local/bin/happ-killswitch ] || sudo /usr/local/bin/happ-killswitch off
	@! sudo nft list table inet happ-ks >/dev/null 2>&1 || { echo "kill switch rules still active — nothing removed" >&2; exit 1; }
	-omarchy plugin disable omarchy-vpn
	rm -rf ~/.config/omarchy/plugins/omarchy-vpn
	-omarchy-shell -q shell rescanPlugins
	rm -rf ~/.local/share/omarchy-vpn
	sed -i '/^-- >>> omarchy-vpn$$/,/^-- <<< omarchy-vpn$$/d' ~/.config/hypr/bindings.lua 2>/dev/null || true
	sudo rm -f /usr/local/bin/happ-killswitch /usr/local/bin/openvpn-dns-updown
	rm -f ~/.config/happ-killswitch.conf
	sudo rm -f /etc/sudoers.d/vpn-manager
	@echo "Uninstalled."

# Lint + test in a container: no host /tmp, /run, /etc/wireguard mounts and
# no network — see Dockerfile.test for why (real happd socket / VPN state
# must never be reachable from a test run).
test-docker-build:
	docker build -t omarchy-vpn-test -f Dockerfile.test .

# Same checks as CI, on the host venv (fast; no live-system isolation —
# for that use test-docker)
lint:
	ruff check src tests
	ruff format --check src tests
	mypy src

test-docker:
	docker run --rm --network none -v "$$PWD":/repo:ro -w /repo omarchy-vpn-test

.PHONY: install uninstall lint test-docker-build test-docker
