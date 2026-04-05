# Disable-CompatTelemetry

> PowerShell script to permanently silence **CompatTelRunner.exe** (Microsoft Compatibility Telemetry) across all attack vectors — Task Scheduler, services, registry policies, and optionally the binary itself via NTFS ACL.

## Why this exists

Setting `AllowTelemetry = 0` via GPO is not enough. CompatTelRunner.exe has multiple independent triggers and can continue running silently even with the standard Group Policy applied. This script closes all known vectors:

| Vector | What it disables |
|--------|-----------------|
| Task Scheduler | `Microsoft Compatibility Appraiser`, `ProgramDataUpdater`, `StartupAppTask`, `AitAgent` — both task state and all triggers |
| Services | `DiagTrack` (Connected User Experiences and Telemetry) + `dmwappushservice` → `Disabled` + stopped |
| Registry | `AllowTelemetry=0` in both policy and non-policy paths; `DisableEngine`, `AITEnable`, `DisableInventory` in AppCompat |
| WER | Windows Error Reporting policy → Disabled |
| Binary ACL *(optional)* | `DENY ExecuteFile` for `Everyone` on `CompatTelRunner.exe` via NTFS ACL |

The `DisableEngine` and `AITEnable` AppCompat keys are the ones that GPO-only approaches miss — they directly disable the compatibility appraisal engine that spawns CompatTelRunner.

## Requirements

- Windows 10 / Windows 11
- PowerShell 5.1 or later
- **Administrator** privileges

## Usage

```powershell
# Standard — covers all registry, service, and scheduler vectors
.\Disable-CompatTelemetry.ps1

# Nuclear — also denies execute permission on the binary via NTFS ACL
.\Disable-CompatTelemetry.ps1 -NuclearAcl
```

Reboot recommended after running to ensure service changes take full effect.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-NuclearAcl` | Switch | `$false` | Adds `DENY ExecuteFile` ACE for `Everyone` on `%SystemRoot%\System32\CompatTelRunner.exe` |

## Notes on `-NuclearAcl`

- Takes ownership of the binary (`takeown /A`) and modifies its DACL
- **Windows Feature Updates reset file ACLs** — re-run the script after each Feature Update
- If you prefer not to touch the binary, the standard run (without `-NuclearAcl`) is sufficient for silencing the process under normal conditions
- The ACL approach is "deny execute" rather than file deletion — this avoids Windows complaining about missing system files while still preventing execution

## Idempotency

The script is safe to run multiple times. All operations are `Set`/`Disable` rather than toggle-based. Re-running after a Windows Update that restored settings will re-apply all restrictions.

## What CompatTelRunner.exe does

`CompatTelRunner.exe` is the **Microsoft Compatibility Telemetry** binary. It:

1. Scans installed applications and hardware for compatibility data
2. Feeds the Windows Compatibility Appraiser (`appraiser.dll`)
3. Transmits diagnostic telemetry to Microsoft via the DiagTrack service
4. Is scheduled to run periodically via Task Scheduler (not as a persistent service)

It is a legitimate Windows component but is known for causing high CPU and disk I/O spikes, particularly on HDDs and lower-end hardware. Disabling it has no functional impact on system stability.

## Reverting

To restore default behavior, re-enable the scheduled tasks in Task Scheduler and set the registry keys back to their defaults (or simply remove the policy keys under `HKLM:\SOFTWARE\Policies\...`).

```powershell
# Re-enable DiagTrack if needed
Set-Service DiagTrack -StartupType Automatic
Start-Service DiagTrack
```

## License

MIT — see [LICENSE](LICENSE).

## Author

Quaerendir
