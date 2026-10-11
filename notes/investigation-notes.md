# Lab 103 — Investigation Notes

## 1. Investigation Summary

The investigation examined Windows Object Manager namespace entries, device symbolic links, and a controlled named mutex on the endpoint `DESKTOP-9MMM37V`. WinObj64 was used to inspect namespace entries, PowerShell was used for evidence collection and test-object creation, and Sysinternals Handle was used to identify the active mutex.

The investigation also reviewed endpoint monitoring services and available Sysmon/Wazuh events. The findings distinguish direct observations from supporting telemetry and avoid inferring malicious intent from the presence of ordinary Windows objects.

## 2. Environment and Preparation

**Evidence directory:** `C:\ObjectManagerLab\Evidence`

The workspace was created successfully. The following artifacts were generated:

- `investigation-start.txt`
- `system-information.txt`
- `global-namespace-notes.txt`
- `process-baseline.csv`
- `process-details.csv`
- `sysmon-process-events.txt`
- `evidence-hashes.csv`

The evidence directory was used to organize the investigation outputs. The supplied command output does not include the contents of every generated file, so the actual contents should be checked before treating each artifact as independently validated.

### Service status

The following services were reported as running:

| Service | Observed status |
|---|---|
| `Sysmon64` | Running |
| `WazuhSvc` | Running |

Service status confirms that the services were running at the time of the check. It does not, by itself, prove that every relevant event was successfully collected or indexed.

## 3. Object Manager Namespace Inspection

WinObj64 displayed the `GLOBAL??` namespace and entries including `D:` and `PhysicalDrive0`.

### Observed symbolic links

| Object | Observed target |
|---|---|
| `D:` | `\Device\HarddiskVolume4` |
| `PhysicalDrive0` | `\Device\Harddisk0\DR0` |

The observed `D:` target maps the DOS-device name to a volume-related device path. The `PhysicalDrive0` target identifies the corresponding physical-disk device path.

These mappings provide a snapshot of the investigated system's namespace. They should not be generalized to other Windows installations because device numbering and mappings can vary between systems.

### Interpretation

The observed entries are consistent with normal Windows device naming. No evidence was supplied showing that either mapping was unauthorized, manipulated, or associated with suspicious activity.

The investigation therefore records the namespace observations as contextual findings rather than security alerts.

## 4. Process Baseline

PowerShell commands collected running-process information and process metadata.

The baseline included:

- Process IDs
- Process names
- Process start times where available
- Parent process IDs
- Executable paths where available
- Command lines where available

The baseline and process details were exported to CSV files. These files can help correlate an observed object with a process and provide context for subsequent investigation.

Some process attributes may be unavailable because of permissions, process protections, or the way Windows exposes process metadata.

## 5. Controlled Named Mutex Investigation

### Test parameters

| Field | Observed value |
|---|---|
| Mutex name | `Global\Lab103_TestMutex` |
| Process | `pwsh.exe` |
| Process ID | `7308` |
| Creation timestamp | `2026-10-11T06:08:48.6344395+05:30` |
| Inspection tool | Sysinternals Handle v5.0 |

The mutex was created using PowerShell's `.NET` `System.Threading.Mutex` class. The test script retained the object for a limited period to allow inspection by another process.

### Handle output

The Handle command returned:

`pwsh.exe pid: 7308 type: Mutant BF4: \BaseNamedObjects\Lab103_TestMutex`

This is direct evidence that Handle observed a `Mutant` object with the test name and associated it with process ID `7308`.

In Windows terminology, a mutant is the kernel object type associated with mutexes. The output provides process and object information that can be used to document the controlled test.

### Interpretation

The test successfully demonstrated that a named mutex can be inspected with a handle-enumeration tool while the owning process is running.

The result is expected for this controlled test and does not indicate malware activity. No evidence was supplied that the mutex was used by an unknown process or served a malicious purpose.

## 6. Sysmon and Wazuh Review

The endpoint's Sysmon and Wazuh services were reported as running. The investigation also captured a Wazuh event view containing a Sysmon Process Create event.

### Observed event

| Field | Value |
|---|---|
| Event ID | `1` |
| Event record ID | `1220670` |
| Event timestamp (UTC) | `2026-10-11 00:47:58.323` |
| Process ID shown | `6108` |
| Visible image prefix | `C:\Windows\System32\backgroundTaskHost...` |

The screenshot contains a truncated image path. The full executable path and other event fields should be retrieved from the event details if needed.

The event's process ID differs from the test PowerShell process ID (`7308`). Based on the supplied evidence, this event cannot be attributed to the mutex test.

### Telemetry interpretation

Sysmon Event ID 1 records process creation. It does not provide a dedicated event for creating a named mutex. A process may create and hold a named mutex without the mutex name appearing in the normal Sysmon process-creation record.

The Wazuh event therefore provides evidence of process telemetry, not direct proof of mutex creation or collection of the test object's name.

A missing match in Wazuh should be recorded as a visibility or correlation limitation until the available data sources and event fields have been checked.

## 7. Evidence Integrity

The investigation ran a PowerShell command to hash files in the evidence directory using SHA-256 and export the results to `evidence-hashes.csv`.

The command completed without displaying an error. However, the supplied screenshot does not show the resulting hashes or a later verification of the manifest contents.

For reproducibility:

1. Confirm that each expected evidence file exists.
2. Review the CSV manifest and verify that the expected files have entries.
3. Recalculate hashes when validating the evidence at a later stage.
4. Record any subsequent changes to the evidence files.
5. Exclude the manifest itself when generating a stable manifest, or document a second-pass manifest separately.

A hash can help identify changes to a file after collection, but the act of hashing alone does not establish the authenticity of the underlying artifact.

## 8. Confirmed Findings

- WinObj64 displayed the `GLOBAL??` namespace.
- The observed `D:` symbolic-link target was `\Device\HarddiskVolume4`.
- The observed `PhysicalDrive0` symbolic-link target was `\Device\Harddisk0\DR0`.
- The controlled mutex was named `Global\Lab103_TestMutex`.
- Handle identified the mutex as a `Mutant` object associated with `pwsh.exe`, PID `7308`.
- Sysmon and Wazuh services were reported as running.
- A Sysmon Process Create event was visible in Wazuh, but its displayed process ID was `6108`.
- Evidence collection and hash-export commands completed without displaying errors.

## 9. Inconclusive or Unverified Findings

- The available Wazuh event has not been correlated with the controlled mutex process.
- The supplied evidence does not show a dedicated event documenting mutex creation.
- The contents and hash values of all generated evidence files have not been independently reviewed.
- The supplied screenshots do not establish whether the test mutex remained visible after the creating process released its handle.

## 10. Final Assessment

The lab demonstrates practical inspection of Windows Object Manager mappings and direct identification of a controlled named mutex. Handle output establishes the association between the test object and the PowerShell process, while the available Sysmon/Wazuh data provides broader process-monitoring context. The supplied evidence does not establish malicious behavior or direct SIEM visibility of the mutex. These limitations should remain explicit in any final assessment.
