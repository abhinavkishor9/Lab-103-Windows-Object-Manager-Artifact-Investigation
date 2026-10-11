# Lab 103 — Investigation Timeline

## 1. Timeline Overview

This timeline records the main activities and observations from the Windows Object Manager investigation. Where an exact timestamp was not captured in the supplied evidence, the activity is recorded without inventing a time.

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

## 2. Object Manager Evidence

### Namespace observations

The `GLOBAL??` namespace displayed the following symbolic links:

| Object | Observed target |
|---|---|
| `D:` | `\Device\HarddiskVolume4` |
| `PhysicalDrive0` | `\Device\Harddisk0\DR0` |

These observations document the device mappings visible on the endpoint during the investigation. They are consistent with normal Windows behavior and are not, by themselves, security indicators.

## 3. Controlled Mutex Evidence

The PowerShell test created the named mutex `Global\Lab103_TestMutex`.

**Recorded details:**

- Process: `pwsh.exe`
- PID: `7308`
- Creation time: `2026-10-11T06:08:48.6344395+05:30`

Handle returned the following observation:

`pwsh.exe pid: 7308 type: Mutant BF4: \BaseNamedObjects\Lab103_TestMutex`

This directly associates the observed named mutex with the controlled PowerShell process. It does not establish that the object had any malicious purpose.

## 4. Telemetry Correlation

A Sysmon Process Create event was visible in Wazuh with the following displayed details:

- Event ID: `1`
- Event record ID: `1220670`
- Timestamp: `2026-10-11 00:47:58.323 UTC`
- Process ID: `6108`
- Visible image prefix: `C:\Windows\System32\backgroundTaskHost...`

The event's displayed PID differs from the test process PID `7308`. The available evidence does not establish a direct relationship between this event and the mutex investigation.

The event should therefore be retained as supporting endpoint telemetry, not presented as proof that Wazuh recorded the mutex creation.

## 5. Evidence Collection

The following evidence artifacts were generated during the investigation:

- `investigation-start.txt`
- `system-information.txt`
- `global-namespace-notes.txt`
- `process-baseline.csv`
- `process-details.csv`
- `sysmon-process-events.txt`
- `evidence-hashes.csv`

The supplied screenshots confirm that the relevant collection commands completed without displaying errors. The contents and hashes should be inspected when performing a formal evidence-integrity review.

## 6. Final Assessment

The investigation confirmed the observed `GLOBAL??` symbolic-link targets and successfully identified a controlled named mutex associated with PowerShell PID `7308`. A Sysmon Process Create event was also visible in Wazuh, but the event shown uses PID `6108` and cannot be attributed to the mutex test from the available evidence. The final assessment should preserve this distinction and avoid treating either normal device mappings or a named mutex as evidence of compromise without additional corroboration.
