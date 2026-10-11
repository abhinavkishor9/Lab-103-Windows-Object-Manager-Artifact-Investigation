# Investigation Timeline

| Sequence | Time | Activity | Evidence / Result |
|---|---|---|---|
| 1 | Not captured | Evidence workspace prepared | `C:\ObjectManagerLab\Evidence` created. |
| 2 | Not captured | Endpoint and service status checked | `Sysmon64` and `WazuhSvc` reported as running. |
| 3 | Not captured | Object Manager namespace inspected | WinObj64 displayed `GLOBAL??`, `D:`, and `PhysicalDrive0`. |
| 4 | Not captured | Symbolic-link targets recorded | `D:` mapped to `\Device\HarddiskVolume4`; `PhysicalDrive0` mapped to `\Device\Harddisk0\DR0`. |
| 5 | Not captured | Process baseline collected | Process baseline and process details exported to CSV. |
| 6 | `2026-10-11 06:08:48 +05:30` | Named mutex created | `Global\Lab103_TestMutex` created by PowerShell process PID `7308`. |
| 7 | During controlled test | Mutex inspected using Handle | Handle identified a `Mutant` object at `\BaseNamedObjects\Lab103_TestMutex` associated with `pwsh.exe`, PID `7308`. |
| 8 | `2026-10-11 00:47:58.323 UTC` | Sysmon Process Create event visible in Wazuh | Event ID `1`, record ID `1220670`, displayed PID `6108`. The supplied evidence does not link this event to the test mutex. |
| 9 | Not captured | Evidence outputs hashed | SHA-256 hash manifest exported to `evidence-hashes.csv`. |
| 10 | Not captured | Findings reviewed | Confirmed observations separated from unverified telemetry correlations. |

