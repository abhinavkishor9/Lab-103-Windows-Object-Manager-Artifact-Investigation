# Lab-103-Windows-Object-Manager-Artifact-Investigation
## Overview
The Windows Object Manager is a core Windows component that maintains a hierarchical namespace of objects used by the operating system, kernel drivers, and applications. These objects include device objects, driver objects, symbolic links, synchronization objects, and other system resources.
During a DFIR investigation, the Object Manager namespace can help an analyst understand how Windows exposes devices and maps familiar names to internal device paths. For example, GLOBAL?? contains globally visible DOS-device symbolic links, while entries such as D: and PhysicalDrive0 may provide mappings to volume or physical-disk device paths. The exact targets should be verified in WinObj64 rather than assumed.
Object Manager artifacts can also provide context during investigations involving suspicious processes, unauthorized software, or unusual named objects. However, normal Windows objects are numerous, and unfamiliar names alone do not establish malicious behavior. Findings must be correlated with process activity, file evidence, and available security telemetry.
### Key namespaces and artifacts

| Namespace or artifact | Investigative purpose |
|---|---|
| `GLOBAL??` | Inspect globally visible DOS-device names and symbolic links. |
| `D:` | Examine a drive-letter mapping and its displayed target. |
| `PhysicalDrive0` | Examine the named physical-disk device mapping. |
| `\Device` | Explore device-related objects. |
| `\Driver` | Examine driver-related objects. |
| `\BaseNamedObjects` | Investigate named synchronization objects, subject to session and visibility differences. |
| `\Sessions` | Explore session-related object organization. |

The lab uses WinObj64 for namespace inspection, PowerShell for evidence collection, Sysinternals Handle for process-handle inspection, and existing Sysmon/Wazuh telemetry for supporting validation.

This lab investigates Windows Object Manager artifacts to understand how Windows exposes device mappings, symbolic links, and named synchronization objects. The investigation uses WinObj64 to inspect the Object Manager namespace, PowerShell to collect endpoint information, Sysinternals Handle to identify an active named mutex, and existing Sysmon and Wazuh telemetry to examine process activity.

The investigation is performed on a Windows 11 endpoint using a controlled test mutex. The objective is to establish what can be directly observed, correlate the test artifact with its owning process, and document telemetry limitations without treating normal Windows objects as suspicious by default.

## Lab Objectives

- Understand the role of the Windows Object Manager in managing kernel objects, device objects, symbolic links, and named synchronization objects.
- Explore Windows Object Manager namespaces using WinObj64 and document representative objects and their properties.
- Examine the `GLOBAL??` namespace and verify the observed symbolic-link targets for `D:` and `PhysicalDrive0`.
- Understand how DOS-device names map to underlying Windows device paths and why these mappings are relevant to forensic investigations.
- Establish a process baseline using PowerShell and collect process identifiers, names, parent process IDs, executable paths, and available command-line information.
- Create a controlled named mutex and inspect its presence using Sysinternals Handle.
- Correlate the observed mutex with its owning PowerShell process using the process ID and handle information.
- Review Sysmon Process Create events and determine whether available telemetry can be correlated with the controlled test.
- Validate Wazuh event visibility while distinguishing process monitoring from direct named-object monitoring.
- Preserve investigation artifacts, document SHA-256 hashes, and maintain a clear record of the evidence collected.
- Differentiate confirmed findings, inconclusive observations, and telemetry gaps without assuming malicious intent from normal Windows objects.
  
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

## Lab Scenario

A SOC analyst is conducting a Windows endpoint investigation to understand how the Windows Object Manager exposes device mappings and named synchronization objects. The investigation begins in WinObj64, where the analyst examines the `GLOBAL??` namespace and observes entries such as `D:` and `PhysicalDrive0`. The objective is to document their actual symbolic-link targets and understand how Windows maps familiar device names to underlying system paths.

To investigate named objects, the analyst creates a harmless test mutex named `Global\Lab103_TestMutex` using PowerShell. While the test process is running, Sysinternals Handle is used to inspect the object and identify its associated process. The observed output identifies a `Mutant` object associated with `pwsh.exe`, process ID `7308`, providing direct evidence of the controlled test artifact.

The investigation then examines the available Sysmon and Wazuh telemetry to determine what process activity can be correlated with the test. A Sysmon Process Create event is visible in Wazuh, but its recorded process ID differs from the test process ID. The analyst must therefore avoid attributing that event to the mutex investigation without additional evidence.

The investigation focuses on the following activities:

- **Namespace inspection:** Examine Object Manager entries and record observed device mappings and symbolic-link targets.
- **Named-object analysis:** Create a controlled mutex and use Handle to inspect its object type, name, and associated process.
- **Process correlation:** Compare process identifiers and timestamps to establish whether observed events relate to the controlled activity.
- **Telemetry validation:** Review available Sysmon and Wazuh events while distinguishing process-creation monitoring from direct mutex visibility.
- **Evidence preservation:** Save investigation outputs, document SHA-256 hashes, and record confirmed findings, uncertainties, and collection limitations.

The lab is successful when the observed device mappings and controlled mutex are documented accurately, the mutex is correlated with its owning process, and the available telemetry is assessed without overstating what it proves. The presence of a named mutex or a normal device mapping is not, by itself, evidence of malicious activity.

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

