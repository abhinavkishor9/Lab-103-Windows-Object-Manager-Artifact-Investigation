# Lab 103 — Troubleshooting Notes

## 1. WinObj64 Namespace Visibility

### Observation

WinObj64 displayed `GLOBAL??` with entries including `D:` and `PhysicalDrive0`.

### Interpretation

The namespace provides visibility into DOS-device names and symbolic links. The precise entries and targets depend on the system's configuration and device mappings.

### Troubleshooting

- Run WinObj64 with administrator privileges if some entries cannot be inspected.
- Record the actual target shown by the tool rather than assuming a standard target.
- If an expected object is absent, check the namespace path and current session.
- Do not modify or delete device objects during the investigation.

The observed targets were:

- `D:` → `\Device\HarddiskVolume4`
- `PhysicalDrive0` → `\Device\Harddisk0\DR0`

These observations were successfully recorded in the investigation notes.

## 2. Handle Executable Not Found

### Initial issue

The command using the example path `C:\Tools\Handle\handle64.exe` failed because PowerShell could not find the executable.

### Resolution

The Handle utility was located at:

`D:\important docs\Handle\handle64.exe`

The corrected command was:

```powershell
& "D:\important docs\Handle\handle64.exe" -a Lab103_TestMutex
```

Quotation marks are necessary because the executable path contains a space.

### Validation

Handle v5.0 returned:

`pwsh.exe pid: 7308 type: Mutant BF4: \BaseNamedObjects\Lab103_TestMutex`

This confirmed that the tool executed successfully and found the test mutex.

## 3. Named Mutex Not Visible in WinObj64

### Potential issue

A named mutex may not appear where expected in the Object Manager tree, or it may not be visible through the currently selected namespace.

### Troubleshooting

1. Confirm that the PowerShell test process is still running.
2. Search for the exact mutex name.
3. Inspect the relevant namespace and session context.
4. Use Handle to search for the object independently.
5. Record which tool observed the object and which did not.

Handle successfully identified the controlled mutex in this investigation. That direct result is stronger evidence of the test object's presence than an unsuccessful search in a single namespace view.

Do not assume that a missing visual entry means the mutex was never created.

## 4. Understanding the `Mutant` Object Type

### Observation

Handle reported the object type as `Mutant`.

### Explanation

Windows uses the kernel object type `Mutant` for mutex objects. The name reflects Windows' internal terminology and does not indicate a malicious or abnormal artifact.

### Recommended action

Record the object name, process ID, process name, and returned object path. Use the surrounding process behavior and other evidence to assess security relevance.

A mutex name alone is not enough to classify an application as malicious.

## 5. Sysmon Event Correlation

### Observation

The Wazuh event view showed Sysmon Event ID `1`, record ID `1220670`, with process ID `6108` and a partially visible image path beginning with `C:\Windows\System32\backgroundTaskHost`.

The controlled mutex was associated with PowerShell process ID `7308`.

### Interpretation

The process IDs differ. The supplied event does not establish that it belongs to the controlled test.

### Troubleshooting

- Search for Sysmon Event ID 1 around the test time.
- Inspect the complete event message and process image.
- Compare the event's process ID and timestamp with the PowerShell test details.
- Check whether the endpoint's local Sysmon Operational log contains a corresponding event.
- Record the event as unrelated or uncorrelated unless supporting evidence establishes the relationship.

Do not attribute a process event to the mutex merely because both appear during the same investigation.

## 6. Wazuh Event Visibility

### Observation

Wazuh displayed a Sysmon Process Create event, but the supplied evidence did not show a dedicated record of the named mutex.

### Explanation

Sysmon Event ID 1 records process creation. It does not provide a dedicated event for creating a named mutex. Wazuh can only display the relevant information that its configured sources collect and index.

### Troubleshooting

1. Confirm that the Wazuh agent service is running.
2. Verify that Sysmon events are being recorded in the local Windows event log.
3. Search Wazuh for recent Sysmon Event ID 1 events.
4. Compare event timestamps and process IDs with the test.
5. Inspect the expanded event JSON to confirm actual field names.

A missing Wazuh alert is not proof that the event was never generated. Security event views may contain alert documents rather than every raw Windows event.

**Configuration note:** Keep Wazuh archives disabled for this lab, as planned. Do not enable additional data collection merely to force a result. Document what the existing configuration can and cannot demonstrate.

## 7. Evidence File and Hash Validation

### Observation

The evidence-generation commands completed without displaying errors, including the SHA-256 export command.

### Troubleshooting

Verify the output files:

```powershell
Get-ChildItem "C:\ObjectManagerLab\Evidence" -File |
    Select-Object Name, Length, LastWriteTime
```

Review the hash manifest:

```powershell
Import-Csv "C:\ObjectManagerLab\Evidence\evidence-hashes.csv" |
    Format-Table Algorithm, Hash, Path -AutoSize
```

Recalculate a selected file's hash when validating it:

```powershell
Get-FileHash `
    "C:\ObjectManagerLab\Evidence\global-namespace-notes.txt" `
    -Algorithm SHA256
```

Compare the result with the corresponding manifest entry. A hash mismatch requires investigation into whether the file changed after the manifest was generated.

## 8. Evidence-Based Reporting

When a result cannot be confirmed, use precise language:

- **Confirmed:** Directly observed by the relevant tool.
- **Not observed:** The selected query or inspection did not return the artifact.
- **Inconclusive:** Available evidence is insufficient to determine the result.
- **Not tested:** The relevant verification was not performed.

For this lab, the mutex's association with PowerShell PID `7308` is confirmed by Handle. The displayed Wazuh event with PID `6108` is not confirmed to be related to the test. Neither finding independently establishes malicious activity.
