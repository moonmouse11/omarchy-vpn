#!/usr/bin/env bash
# Host runner: boots an existing sealed image on vm-boot's throwaway overlay.
# No host install, desktop/service changes or network tunnels. The guest gets
# a read-only repo share and a writable evidence directory only.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "Usage: bash tests/run_qml_vm.sh /path/to/vm-boot /path/to/sealed-image.qcow2" >&2
    exit 64
fi
boot=$(realpath "$1")
image=$(realpath "$2")
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
[[ -x $boot && -r $image ]] || { echo "Missing sealed image or vm-boot" >&2; exit 1; }
mkdir -p "$repo/.cache"
output=$(mktemp -d "$repo/.cache/qml-vm-audit.XXXXXX")
# vm-boot splits QEMU_EXTRA on whitespace; QEMU splits -virtfs fields on commas.
[[ $repo$output != *[[:space:],]* ]] || { echo "VM share paths must not contain whitespace/commas" >&2; exit 1; }
export APPEND="${APPEND:-} omarchy_vpn_test=1"
export MEM=${MEM:-3G}
export QEMU_EXTRA="-virtfs local,path=$repo,mount_tag=repo,security_model=none,readonly=on -virtfs local,path=$output,mount_tag=out,security_model=none"
# vm-boot owns VM shutdown/overlay cleanup even when the gate fails.
echo "VM evidence: $output"
"$boot" "$image" env OMARCHY_VPN_DISPOSABLE_GUEST=1 bash -s < "$repo/tests/qml_vm_guest.sh" 2>&1 | tee "$output/run.log"
[[ $(< "$output/result.txt") == PASS ]]
echo "PASS — evidence: $output"
