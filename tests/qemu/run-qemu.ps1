# CaelumOS M1-M4 QEMU/OVMF acceptance runner (PowerShell) — thin wrapper.
#
# The markers, the QEMU command line, the serial (bidirectional chardev) and
# PS/2 keyboard (QMP send-key) injection all live in `cargo xtask qemu`, so this
# script intentionally contains NO marker list and NO QEMU arguments: a single
# source of truth cannot drift.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tests\qemu\run-qemu.ps1
#   powershell -ExecutionPolicy Bypass -File tests\qemu\run-qemu.ps1 -Timeout 180
#   powershell -ExecutionPolicy Bypass -File tests\qemu\run-qemu.ps1 -Ovmf C:\path\OVMF_CODE.fd
#
# M4 adds no input: 'cargo xtask image' packs the initramfs into /INITFS.IMG and the guest
# prints the M4 markers (and the trailing deliberate M2 #PF) on its own.
# Exit codes: 0 = acceptance OK, or QEMU/OVMF unavailable (skip); 1 = failure.

param(
    # Kept for backward compatibility only: xtask owns these paths now.
    [string]$Image = "",
    [string]$Log = "",
    # OVMF firmware override; falls back to $env:CAELUM_OVMF, then tools/ovmf.
    [string]$Ovmf = "",
    # Overall timeout in seconds (cargo xtask qemu's CAELUM_QEMU_TIMEOUT).
    [int]$Timeout = 0
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

if ($Image -or $Log) {
    Write-Host "[run-qemu] note: -Image/-Log are managed by 'cargo xtask qemu'; ignoring them."
    Write-Host "[run-qemu]       image: target/caelum-esp.img   log: target/serial.log"
}
if ($Ovmf) { $env:CAELUM_OVMF = $Ovmf }
if ($Timeout -gt 0) { $env:CAELUM_QEMU_TIMEOUT = "$Timeout" }

Push-Location $Root
try {
    & cargo xtask qemu
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($code -ne 0) {
    Write-Host "[run-qemu] FAIL (cargo xtask qemu exited $code)"
    exit 1
}
exit 0
