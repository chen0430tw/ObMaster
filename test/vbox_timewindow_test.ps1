# vbox_timewindow_test.ps1
# Test: spin-close evil kernel handles in PID 4 -> see if VirtualBox can survive
#
# Uses ObMaster /handle-scan 4 --close to walk the kernel HANDLE_TABLE directly.
# NtQuerySystemInformation cannot see OBJ_KERNEL_HANDLE entries; ObMaster can.
#
# Usage (elevated PowerShell):
#   .\vbox_timewindow_test.ps1 [-VmName "Ubuntu"] [-Rounds 3] [-SpinMs 3000]

param(
    [string]$VmName  = "Ubuntu",
    [int]   $Rounds  = 3,
    [int]   $SpinMs  = 3000
)

$OBM    = "$PSScriptRoot\..\ObMaster.exe"
$VBOXVM = "C:\Program Files\Oracle\VirtualBox\VirtualBoxVM.exe"
$VBOXLOG = "$env:USERPROFILE\VirtualBox VMs\$VmName\Logs\VBoxHardening.log"

if (-not (Test-Path $OBM))    { Write-Error "ObMaster not found: $OBM";    exit 1 }
if (-not (Test-Path $VBOXVM)) { Write-Error "VirtualBoxVM not found";       exit 1 }

# ---------------------------------------------------------------------------
# Close all PROCESS_ALL_ACCESS handles in PID 4 via ObMaster kernel walk
# Returns number of handles actually zeroed
# ---------------------------------------------------------------------------
function Close-KernelHandles {
    $out = & $OBM /quiet /handle-scan 4 --close 2>&1
    $found  = ($out | Select-String '\[\+\] h=').Count
    $closed = ($out | Select-String '\[x\] h=').Count
    if ($found -gt 0) {
        Write-Host "      [ObMaster] found=$found closed=$closed" -ForegroundColor Magenta
        $out | Where-Object { $_ -match '\[.\] h=' } | ForEach-Object {
            Write-Host "        $_" -ForegroundColor DarkMagenta
        }
    }
    return $closed
}

# ---------------------------------------------------------------------------
# Get last N lines of VBoxHardening.log
# ---------------------------------------------------------------------------
function Get-HardeningLog([int]$Lines = 20) {
    if (Test-Path $VBOXLOG) { Get-Content $VBOXLOG -Tail $Lines }
    else { "(log not found: $VBOXLOG)" }
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
Write-Host "`n=== VirtualBox Time-Window Test (ObMaster kernel handle-scan) ===" -ForegroundColor Yellow
Write-Host "VM     : $VmName"
Write-Host "Rounds : $Rounds   SpinMs: $SpinMs"
Write-Host "OBM    : $OBM"
Write-Host ""

for ($round = 1; $round -le $Rounds; $round++) {
    Write-Host "--- Round $round/$Rounds ---" -ForegroundColor Green

    # 1. Pre-clean: close any leftover evil handles before launch
    Write-Host "[1] Pre-launch: closing existing PID-4 PROCESS_ALL_ACCESS handles..."
    $pre = Close-KernelHandles
    Write-Host "    Pre-closed: $pre"

    # 2. Launch VirtualBox (non-blocking)
    Write-Host "[2] Launching VirtualBox --startvm $VmName"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $vp = Start-Process -FilePath $VBOXVM -ArgumentList "--startvm", $VmName `
                        -PassThru -ErrorAction SilentlyContinue
    if (-not $vp) {
        Write-Host "    ERROR: failed to start VirtualBoxVM.exe" -ForegroundColor Red
        continue
    }
    Write-Host "    PID: $($vp.Id)"

    # 3. Spin-close loop via ObMaster kernel HANDLE_TABLE walk
    Write-Host "[3] Spin-close loop for ${SpinMs}ms (100ms interval)..."
    $totalClosed = 0
    $spinEnd = (Get-Date).AddMilliseconds($SpinMs)
    while ((Get-Date) -lt $spinEnd -and -not $vp.HasExited) {
        $n = Close-KernelHandles
        if ($n -gt 0) {
            $totalClosed += $n
            $ms = [int]$sw.ElapsedMilliseconds
            Write-Host "    [+${ms}ms] closed $n  total=$totalClosed" -ForegroundColor Cyan
        }
        Start-Sleep -Milliseconds 100
    }
    Write-Host "    Spin done — total closed during window: $totalClosed"

    # 4. Wait for VirtualBox to exit (or succeed)
    Write-Host "[4] Waiting up to 20s for VirtualBox result..."
    $vp.WaitForExit(20000) | Out-Null

    if (-not $vp.HasExited) {
        Write-Host "    => STILL RUNNING after 20s — likely SUCCESS!" -ForegroundColor Green
    } elseif ($vp.ExitCode -eq 0) {
        Write-Host "    => Exited cleanly (code=0)" -ForegroundColor Green
    } else {
        $code = [uint32]$vp.ExitCode
        Write-Host ("    => Failed (exit=0x{0:X8})" -f $code) -ForegroundColor Red
    }

    # 5. Check hardening log
    Write-Host "[5] VBoxHardening.log:"
    if (Test-Path $VBOXLOG) {
        $log = Get-Content $VBOXLOG -ErrorAction SilentlyContinue
        $evil = $log | Select-String "evil|3738|VERR_SUP"
        if ($evil) {
            Write-Host "    [EVIL-HANDLE LINES FOUND]:" -ForegroundColor Red
            $evil | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
        } else {
            Write-Host "    (no evil-handle lines — passed that check)" -ForegroundColor Green
        }
        Write-Host "    [last 8 lines]:"
        Get-HardeningLog 8 | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "    (log not found: $VBOXLOG)"
    }

    # 6. Kill leftover process before next round
    if (-not $vp.HasExited) {
        Write-Host "[6] Killing VirtualBox..."
        $vp.Kill()
    }

    Write-Host ""
    if ($round -lt $Rounds) { Start-Sleep -Seconds 2 }
}

Write-Host "=== Test complete ===" -ForegroundColor Yellow
