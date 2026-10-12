install:
	@bash install.sh

uninstall:
	-omarchy plugin disable omarchy-vpn
	rm -rf ~/.config/omarchy/plugins/omarchy-vpn
	-omarchy-shell -q shell rescanPlugins
	rm -rf ~/.local/share/omarchy-vpn
	sed -i '/^-- >>> omarchy-vpn$$/,/^-- <<< omarchy-vpn$$/d' ~/.config/hypr/bindings.lua 2>/dev/null || true
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
