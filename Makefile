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

# Opt-in bundled Ferrum checks: point at an extracted official /opt/incy tree.
# Root helpers and native core run only inside this disposable network namespace.
test-incy-docker-build:
	docker build -t omarchy-vpn-incy-test -f Dockerfile.incy-test .

test-incy-docker: test-incy-docker-build
	@test -f "$(INCY_TEST_ROOT)/lib/app/resources/bin/libincycore.so" || \
		{ echo 'Set INCY_TEST_ROOT to the extracted official /opt/incy directory'; exit 1; }
	docker run --rm --hostname incy-test --add-host incy-test:127.0.0.1 \
		--network none --read-only --cap-drop ALL \
		--cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SYS_ADMIN \
		--cap-add SETUID --cap-add SETGID --cap-add KILL --cap-add CHOWN --cap-add DAC_OVERRIDE \
		--device /dev/net/tun --tmpfs /run:rw,mode=755 --tmpfs /tmp:rw,mode=1777 \
		-v "$$PWD":/repo:ro -v "$(INCY_TEST_ROOT)":/inspect:ro omarchy-vpn-incy-test

.PHONY: install uninstall lint test-docker-build test-docker test-incy-docker-build test-incy-docker
