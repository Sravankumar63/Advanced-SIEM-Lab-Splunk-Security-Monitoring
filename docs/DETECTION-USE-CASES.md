# Detection Use Cases and SPL Examples

These examples reflect the use cases documented in the project report. They are starting points, not universal detections: event field names, sourcetypes, indexes, and Windows audit policies differ between environments. Verify results against actual collected events before using them as alerts.

## 1. Failed Windows authentication — Event ID 4625

```spl
index=* host="Ricky" sourcetype="WinEventLog:Security" EventCode=4625
| table _time Account_Name Source_Network_Address Workstation_Name Failure_Reason
| sort - _time
```

**Purpose:** Review failed logon events, timestamps, account names, source information, and failure reason. The report documents a failed-login alert and a threshold-based alert. Repeated failures should be investigated in context; a failed logon alone does not prove malicious activity.

## 2. Nmap network reconnaissance

The lab ran service/version detection and a SYN scan from Kali against the Windows endpoint:

```bash
nmap -sV 192.168.196.128
nmap -sS 192.168.196.128
```

The report describes searching Windows Filtering Platform Event ID 5156 and grouping observed destination ports by the Kali source address:

```spl
index=* host="Ricky" sourcetype="WinEventLog:Security" EventCode=5156 Source_Address="192.168.196.130"
| stats dc(Destination_Port) as unique_ports count by Source_Address
```

**Purpose:** Identify observed network connections and port diversity during a controlled scan. Event ID 5156 records permitted connections when the relevant Windows Filtering Platform auditing is enabled; it is not, by itself, a definitive Nmap signature.

## 3. SQL injection in DVWA

DVWA was hosted locally on Windows through XAMPP. The controlled test used the SQL Injection page with the application's security setting at Low. Apache access logs were forwarded and searched in Splunk.

A broad initial search can locate requests in the ingested Apache log:

```spl
index=* (sourcetype=access_combined OR sourcetype=access_common OR source="*access.log*")
| search "' OR " OR "%27" OR "UNION" OR "union"
| table _time host clientip method uri status
| sort - _time
```

Adjust the sourcetype and field names to match your actual Apache input. URL encoding and application behavior may change the representation of a payload in logs. Treat keyword matches as investigation leads, not proof by themselves.

**Important evidence note:** The report says the request was generated locally on Windows and the source appeared as `::1`. Do not label this test as originating from Kali unless separate log evidence supports that conclusion.

## 4. PowerShell script-block activity — Event ID 4104

```spl
index=* host="Ricky" sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| table _time host EventCode Message
| sort - _time
```

**Purpose:** Confirm collection of PowerShell Operational script-block events and review the recorded message. Event 4104 availability depends on PowerShell logging configuration and the forwarder's channel input.

## 5. Alert configuration notes

The project report documents these saved alerts:

- `Nmap Network Reconnaissance Detection`
- `Windows Failed Login - Threshold Detection`
- `Windows Failed Login Detection`
- `Nmap SYN Scan Detection`
- `Web SQL Injection Detection`

For each alert, document its search, time range, schedule, trigger condition, throttling (if used), and action. The alert name alone does not establish its schedule or notification behavior.
