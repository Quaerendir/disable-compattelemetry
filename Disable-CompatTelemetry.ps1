#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disable CompatTelRunner.exe (Microsoft Compatibility Telemetry) across all vectors.
.DESCRIPTION
    Covers: Task Scheduler tasks, DiagTrack service, registry telemetry policy,
    optional NTFS ACL deny-execute (nuclear option, -NuclearAcl switch).

    Run as Administrator. Compatible with Windows 10 and Windows 11.
.PARAMETER NuclearAcl
    If specified, adds a DENY ExecuteFile ACE for Everyone on CompatTelRunner.exe.
    Survives GPO resets but is reset by Windows Feature Updates — re-run after each.
.EXAMPLE
    .\Disable-CompatTelemetry.ps1
.EXAMPLE
    .\Disable-CompatTelemetry.ps1 -NuclearAcl
.NOTES
    Author : Quaerendir
    License: MIT
    Repo   : https://github.com/quaerendir/disable-compattelemetry
#>

param(
    [switch]$NuclearAcl
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK([string]$msg)   { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

# ─────────────────────────────────────────────────────────────────
# 1. Task Scheduler – Application Experience tasks
# ─────────────────────────────────────────────────────────────────
Write-Step "Disabling Task Scheduler tasks..."

$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Application Experience\AitAgent"
)

foreach ($task in $tasks) {
    try {
        $t = Get-ScheduledTask -TaskPath (Split-Path $task) `
             -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue
        if ($t) {
            $s = $t.Settings
            $s.Enabled = $false
            Set-ScheduledTask -TaskPath (Split-Path $task) `
                -TaskName (Split-Path $task -Leaf) -Settings $s | Out-Null
            Disable-ScheduledTask -TaskPath (Split-Path $task) `
                -TaskName (Split-Path $task -Leaf) | Out-Null
            Write-OK "Disabled: $task"
        } else {
            Write-Warn "Not found (may not exist on this OS version): $task"
        }
    } catch {
        Write-Warn "Failed to disable ${task}: $_"
    }
}

# ─────────────────────────────────────────────────────────────────
# 2. DiagTrack + dmwappushservice (telemetry transport layer)
# ─────────────────────────────────────────────────────────────────
Write-Step "Disabling telemetry services..."

foreach ($svc in @("DiagTrack", "dmwappushservice")) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled
        Write-OK "$svc stopped and set to Disabled"
    } catch {
        Write-Warn "${svc}: $_"
    }
}

# ─────────────────────────────────────────────────────────────────
# 3. Registry – AllowTelemetry + AppCompat engine policies
# ─────────────────────────────────────────────────────────────────
Write-Step "Setting registry telemetry policies..."

$regKeys = @(
    # Machine-scope DataCollection policy (GPO-equivalent)
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Name  = "AllowTelemetry"
        Value = 0
    },
    # Non-policy path used when no GPO is applied
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        Name  = "AllowTelemetry"
        Value = 0
    },
    # CEIP (Customer Experience Improvement Program)
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
        Name  = "CEIPEnable"
        Value = 0
    },
    # AppCompat Engine – direct feeder of CompatTelRunner
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name  = "DisableEngine"
        Value = 1
    },
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name  = "AITEnable"
        Value = 0
    },
    [pscustomobject]@{
        Path  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
        Name  = "DisableInventory"
        Value = 1
    }
)

foreach ($reg in $regKeys) {
    try {
        if (-not (Test-Path $reg.Path)) {
            New-Item -Path $reg.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type DWord -Force
        Write-OK "Set $($reg.Path)\$($reg.Name) = $($reg.Value)"
    } catch {
        Write-Warn "Registry $($reg.Path)\$($reg.Name): $_"
    }
}

# ─────────────────────────────────────────────────────────────────
# 4. Windows Error Reporting (bonus – feeds telemetry pipeline)
# ─────────────────────────────────────────────────────────────────
Write-Step "Disabling Windows Error Reporting..."
try {
    $werPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    if (-not (Test-Path $werPath)) { New-Item -Path $werPath -Force | Out-Null }
    Set-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -Type DWord -Force
    Write-OK "WER policy set to Disabled"
} catch {
    Write-Warn "WER: $_"
}

# ─────────────────────────────────────────────────────────────────
# 5. NUCLEAR ACL option (-NuclearAcl switch required)
#    Adds DENY ExecuteFile for Everyone on the binary itself.
#    NOTE: Windows Feature Updates reset file ACLs. Re-run after updates.
# ─────────────────────────────────────────────────────────────────
if ($NuclearAcl) {
    Write-Step "Nuclear ACL: denying execute on CompatTelRunner.exe..."
    $bin = "$env:SystemRoot\System32\CompatTelRunner.exe"

    if (Test-Path $bin) {
        try {
            $null = & takeown.exe /F $bin /A 2>&1
            $null = & icacls.exe  $bin /grant "Administrators:F" 2>&1

            $acl  = Get-Acl $bin
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]::ExecuteFile,
                [System.Security.AccessControl.AccessControlType]::Deny
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path $bin -AclObject $acl
            Write-OK "DENY ExecuteFile -> Everyone on $bin"
            Write-Warn "Feature Updates reset file ACLs. Re-run this script after each Feature Update."
        } catch {
            Write-Warn "ACL modification failed: $_"
        }
    } else {
        Write-Warn "Binary not found at $bin (already removed?)"
    }
}

# ─────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=======================================================" -ForegroundColor Magenta
Write-Host " CompatTelRunner hardening complete." -ForegroundColor Magenta
Write-Host " Reboot recommended for service changes to fully apply." -ForegroundColor Magenta
if (-not $NuclearAcl) {
    Write-Host " Tip: add -NuclearAcl to also deny execute on the binary." -ForegroundColor DarkGray
}
Write-Host "=======================================================" -ForegroundColor Magenta