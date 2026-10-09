# Implementation Guide

This guide summarizes the implemented setup described in the project report. Commands and paths are reproduced where documented; validate them against your own VM configuration before running them.

## 1. Lab topology

| VM | Role | Address |
|---|---|---|
| Kali Linux 2026.2 | Security testing | `192.168.196.130` |
| Windows 11 Pro | Monitored endpoint | `192.168.196.128` |
| Ubuntu Server 26.04.1 LTS | Splunk SIEM server | `192.168.196.132` |

The virtual systems communicate over the VMware custom network `192.168.196.0/24`.

## 2. Prepare Ubuntu Server

After installation, verify the assigned address and update packages:

```bash
ip addr
sudo apt update && sudo apt upgrade -y
```

## 3. Install Splunk Enterprise

Install Splunk Enterprise 10.4.3 on Ubuntu Server and start the service according to the package's installation instructions. Access Splunk Web from a system that can reach the lab server:

```text
http://192.168.196.132:8000
```

Configure a receiving port for forwarder traffic on TCP `9997`. Keep the Web interface and receiver restricted to the lab network.

## 4. Install the Windows Universal Forwarder

Install Splunk Universal Forwarder 10.4.3 on Windows 11. Configure the forwarder's destination in:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf
```

The configured destination is:

```text
192.168.196.132:9997
```

Test reachability from Windows PowerShell:

```powershell
Test-NetConnection 192.168.196.132 -Port 9997
```

After updating the destination, restart the Splunk Universal Forwarder service and verify that Windows events arrive in Splunk. Exact service-control commands can depend on the installation and permissions.

## 5. Validate Windows event collection

The report uses host `Ricky` in searches. First inspect the actual events arriving from that host:

```spl
index=* host="Ricky"
```

Enable PowerShell Operational logging from an elevated PowerShell prompt:

```powershell
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true
```

Search for script-block logging events:

```spl
index=* host="Ricky" sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
```

If a search returns no results, verify the channel is enabled, the Universal Forwarder input includes the channel, and the selected time range covers the test.

## 6. Web application test environment

The Windows endpoint hosted DVWA through XAMPP, using Apache and MySQL. The documented SQL injection exercise used DVWA's SQL Injection page with its security setting at Low and a controlled test payload:

```text
' OR '1'='1' #
```

This is a deliberately vulnerable application test, not a payload to use against systems without authorization. Apache access logs were added to the forwarder's inputs and searched in Splunk. The documented request originated locally on Windows and appeared as `::1`.

## 7. Configure searches, alerts, and dashboard

Once ingestion is verified:

1. Run the detection searches documented in [Detection Use Cases](DETECTION-USE-CASES.md).
2. Review event fields and timestamps before saving a search.
3. Configure alert conditions and schedules appropriate to the lab.
4. Open Dashboard Studio and save the dashboard as **SOC Security Monitoring Dashboard**.
5. Validate each panel against its underlying search and selected time range.

## Troubleshooting checklist

- Confirm all VMs are on the intended VMware network and can reach one another.
- Confirm Splunk Enterprise is running and the receiver is enabled on TCP 9997.
- Confirm Windows can reach `192.168.196.132:9997`.
- Check `outputs.conf` if events are not forwarded.
- Confirm the relevant Windows event channel is enabled and configured as a forwarder input.
- Check index, host, sourcetype, event code, and time range before assuming an event was not collected.
- Do not publish credentials, tokens, or unredacted sensitive event data.
