# Manually boot CaelumOS with guest serial output in the current terminal.
# By default, rebuild the ESP and reuse the existing FAT32/ext2 test disks.
param(
    [switch]$NoBuild,   # Skip cargo xtask image.
    [switch]$Fresh,     # Run the full two-boot acceptance first to recreate disks.
    [switch]$Gui,       # Also open a QEMU window; serial remains in the terminal.
    [switch]$WhatIf,    # Print the QEMU command without starting it.
    [string]$Ovmf = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $Root
try {
    $esp = Join-Path $Root "target\caelum-esp.img"
    $fat = Join-Path $Root "target\m5b-fat32.img"
    $ext2 = Join-Path $Root "target\m5b-ext2.img"

    if ($Fresh -or -not (Test-Path $fat) -or -not (Test-Path $ext2)) {
        Write-Host "[manual-qemu] Running the full two-boot acceptance to create fresh disks..."
        & cargo xtask qemu
        if ($LASTEXITCODE -ne 0) { throw "cargo xtask qemu failed with exit code $LASTEXITCODE" }
    } elseif (-not $NoBuild) {
        & cargo xtask image
        if ($LASTEXITCODE -ne 0) { throw "cargo xtask image failed with exit code $LASTEXITCODE" }
    }

    foreach ($image in @($esp, $fat, $ext2)) {
        if (-not (Test-Path $image)) { throw "Missing image: $image" }
    }

    $qemu = (Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue).Source
    if (-not $qemu) {
        $candidates = @(
            "C:\Program Files\qemu\qemu-system-x86_64.exe",
            "C:\Program Files\QEMU\qemu-system-x86_64.exe",
            "C:\Program Files (x86)\qemu\qemu-system-x86_64.exe",
            "C:\qemu\qemu-system-x86_64.exe",
            "C:\tools\qemu\qemu-system-x86_64.exe",
            "C:\msys64\mingw64\bin\qemu-system-x86_64.exe"
        )
        $qemu = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $qemu) { throw "qemu-system-x86_64 was not found. Install QEMU or add it to PATH." }

    if (-not $Ovmf) {
        if ($env:CAELUM_OVMF) {
            $Ovmf = $env:CAELUM_OVMF
        } else {
            $Ovmf = Join-Path $Root "tools\ovmf\OVMF_CODE.fd"
        }
    }
    if (-not (Test-Path $Ovmf)) { throw "OVMF was not found: $Ovmf (use -Ovmf to override)" }

    $qemuArgs = @(
        "-machine", "q35",
        "-smp", "4",
        "-m", "256M",
        "-drive", "if=pflash,format=raw,readonly=on,file=$Ovmf",
        "-drive", "file=$esp,format=raw,if=ide",
        "-drive", "if=none,id=disk0,format=raw,file=$fat",
        "-device", "virtio-blk-pci,drive=disk0,disable-modern=on,disable-legacy=off,queue-size=128",
        "-drive", "if=none,id=disk1,format=raw,file=$ext2",
        "-device", "virtio-blk-pci,drive=disk1,disable-modern=on,disable-legacy=off,queue-size=128",
        "-serial", "stdio",
        "-monitor", "none",
        "-no-reboot",
        "-no-shutdown"
    )
    if (-not $Gui) { $qemuArgs += @("-display", "none") }

    Write-Host "[manual-qemu] $qemu $($qemuArgs -join ' ')"
    Write-Host "[manual-qemu] Guest serial output appears here. Press Ctrl+A, then X to quit QEMU."
    if ($WhatIf) { exit 0 }

    & $qemu @qemuArgs
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
