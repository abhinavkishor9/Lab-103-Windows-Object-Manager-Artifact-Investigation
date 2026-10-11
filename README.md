# Lab 103 — Windows Object Manager Artifact Investigation

## Overview

This lab investigates Windows Object Manager artifacts to understand how Windows exposes device mappings, symbolic links, and named synchronization objects. The investigation uses WinObj64 to inspect the Object Manager namespace, PowerShell to collect endpoint information, Sysinternals Handle to identify an active named mutex, and existing Sysmon and Wazuh telemetry to examine process activity.

The investigation is performed on a Windows 11 endpoint using a controlled test mutex. The objective is to establish what can be directly observed, correlate the test artifact with its owning process, and document telemetry limitations without treating normal Windows objects as suspicious by default.

## Objectives

- Explore Windows Object Manager namespaces and identify representative objects.
- Inspect the `GLOBAL??` namespace and document observed symbolic-link targets.
- Examine the relationship between DOS-device names and underlying device paths.
- Create a harmless named mutex for controlled artifact investigation.
- Use Sysinternals Handle to identify the mutex and associate it with a running process.
- Collect process information and relevant Sysmon events.
- Examine available Wazuh telemetry and distinguish process visibility from direct object visibility.
- Preserve investigation notes, supporting evidence, and SHA-256 hashes.
- Document confirmed findings, inconclusive observations, and collection limitations.

## Environment

| Component | Details |
|---|---|
| Operating system | Windows 11 Pro |
| Endpoint | `DESKTOP-9MMM37V` |
| PowerShell | PowerShell 7 |
| Object Manager inspection | WinObj64 |
| Handle inspection | Sysinternals Handle v5.0 |
| Endpoint monitoring | Sysmon |
| SIEM / log monitoring | Wazuh Agent 4.12.0 |
| Evidence directory | `C:\ObjectManagerLab\Evidence` |

## Investigation Scenario

A SOC analyst is examining Windows Object Manager artifacts to understand device mappings and investigate whether a named synchronization object can be associated with a running process. The analyst begins by inspecting the `GLOBAL??` namespace, where entries such as `D:` and `PhysicalDrive0` are visible.

A controlled named mutex, `Global\Lab103_TestMutex`, is then created through PowerShell. Sysinternals Handle identifies the corresponding `Mutant` object and associates it with the PowerShell process, providing direct evidence of the test artifact and its process association.

The investigation also reviews Sysmon process-creation telemetry and the status of the Wazuh agent. Because process-creation events do not inherently document mutex creation, the analysis distinguishes direct handle inspection from SIEM-based process monitoring.

## Investigation Workflow

1. Prepare the evidence workspace and record endpoint information.
2. Inspect `GLOBAL??` and document the observed device mappings.
3. Explore additional Object Manager namespaces.
4. Collect a baseline of running processes and process metadata.
5. Create the controlled named mutex.
6. Use Sysinternals Handle to inspect the mutex and identify its owning process.
7. Review Sysmon and Wazuh telemetry for relevant process activity.
8. Document confirmed observations, limitations, and evidence hashes.

## Key Findings

### 1. Object Manager Namespace

WinObj64 displayed the `GLOBAL??` namespace and entries including `D:` and `PhysicalDrive0`.

The observed symbolic-link targets were:

- `D:` → `\Device\HarddiskVolume4`
- `PhysicalDrive0` → `\Device\Harddisk0\DR0`

These mappings document the names and targets visible on the investigated endpoint. Their presence is consistent with normal Windows device naming and does not indicate malicious activity.

### 2. Controlled Named Mutex

The test mutex was created with the name `Global\Lab103_TestMutex`.

Recorded test details:

- Process ID: `7308`
- Creation timestamp: `2026-10-11T06:08:48.6344395+05:30`
- Process: `pwsh.exe`

Sysinternals Handle returned:

`pwsh.exe pid: 7308 type: Mutant BF4: \BaseNamedObjects\Lab103_TestMutex`

This directly confirms that Handle observed the named mutex associated with the PowerShell process during the test.

### 3. Endpoint Telemetry

Sysmon and Wazuh services were running when their status was checked. A Wazuh event view showed a Sysmon Process Create event with event ID `1` and record ID `1220670`.

The displayed event contained a different process ID (`6108`) and a partially visible image path beginning with `C:\Windows\System32\backgroundTaskHost...`. The available screenshot does not establish that this event corresponds to the test mutex process.

### 4. Evidence Collection

The investigation collected or generated:

- System information
- Investigation start timestamp
- `GLOBAL??` namespace notes
- Process baseline
- Process details
- Sysmon process-event output
- SHA-256 evidence manifest

The supplied command output confirms that the collection and export commands completed without displaying errors. The individual file contents and hash values should be reviewed if further validation is required.

## Limitations

- The Object Manager namespace can vary by Windows version, session, and privilege level.
- Handle output establishes process association for the observed mutex but does not establish malicious behavior.
- Sysmon Process Create events do not provide a dedicated record of named mutex creation.
- The supplied Wazuh event does not establish a direct correlation with the controlled test process.
- The absence of a matching Wazuh event would not prove that the mutex was never created.
- No evidence in this investigation establishes that the tested object was malicious.

## Conclusion

The investigation successfully documented selected Windows device mappings and verified a controlled named mutex using Sysinternals Handle. The mutex was associated with PowerShell process ID `7308`, demonstrating how a named Object Manager artifact can be examined and correlated with its owning process. Sysmon and Wazuh provided additional process-monitoring context, but the available telemetry does not independently confirm mutex creation. The findings support a documented, evidence-based assessment without attributing malicious intent to normal Windows objects.

## Skills Demonstrated

- Windows Object Manager investigation
- Windows symbolic-link analysis
- PowerShell evidence collection
- Process and handle inspection
- Sysinternals WinObj64 and Handle
- Sysmon process-event analysis
- Wazuh telemetry validation
- Evidence documentation and SHA-256 hashing
- DFIR reporting and uncertainty management
