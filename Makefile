install:
	@bash install.sh

uninstall:
	@bash uninstall.sh

# Lint + test in a container: no host /tmp, /run, /etc/wireguard mounts and
# no network — see Dockerfile.test for why (real happd socket / VPN state
# must never be reachable from a test run).
test-docker-build:
	docker build -t omarchy-vpn-test -f Dockerfile.test .

# Same checks as CI, with uv.lock's tool versions (fast; no live-system
# isolation — for that use test-docker)
lint:
	uv run --locked ruff check src tests
	uv run --locked ruff format --check src tests
	uv run --locked mypy src

test-docker:
	docker run --rm --network none -v "$$PWD":/repo:ro -w /repo omarchy-vpn-test

.PHONY: install uninstall lint test-docker-build test-docker
