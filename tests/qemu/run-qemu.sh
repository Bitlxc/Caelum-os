#!/usr/bin/env bash
# CaelumOS M1-M4 QEMU/OVMF acceptance runner (bash/Git Bash) — thin wrapper.
#
# The markers, the QEMU command line, the bidirectional serial chardev and the
# PS/2 keyboard (QMP send-key) injection all live in `cargo xtask qemu`, so this
# script intentionally contains NO marker list and NO QEMU arguments: a single
# source of truth cannot drift.
#
# Usage:
#   bash tests/qemu/run-qemu.sh
#   CAELUM_QEMU_TIMEOUT=180 bash tests/qemu/run-qemu.sh
#   CAELUM_OVMF=/c/path/OVMF_CODE.fd bash tests/qemu/run-qemu.sh
#
# M4 adds no input: 'cargo xtask image' packs the initramfs into /INITFS.IMG and the guest
# prints the M4 markers (and the trailing deliberate M2 #PF) on its own.
# Exit codes: 0 = acceptance OK, or QEMU/OVMF unavailable (skip); 1 = failure.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1

# Accept the historical optional timeout argument as well.
if [ "${1:-}" = "--timeout" ] && [ -n "${2:-}" ]; then
    CAELUM_QEMU_TIMEOUT="$2"
    export CAELUM_QEMU_TIMEOUT
fi

cargo xtask qemu
code=$?

if [ "$code" -ne 0 ]; then
    echo "[run-qemu] FAIL (cargo xtask qemu exited $code)"
    exit 1
fi
exit 0
