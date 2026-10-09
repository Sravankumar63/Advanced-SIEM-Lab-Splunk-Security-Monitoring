# Investigation Workflow and Findings

## Workflow

1. **Generate a controlled event** in the isolated lab (failed Windows logon, Nmap scan, DVWA SQL injection test, or PowerShell activity).
2. **Validate ingestion** in Splunk and confirm the expected host, index, sourcetype, event code, timestamp, and relevant fields.
3. **Run a focused search** to isolate the activity and review related events around the same time.
4. **Investigate context:** source and destination, account, requested URI, port, process/script message, and whether the behavior was expected.
5. **Use the configured alert and dashboard** to surface and summarize activity.
6. **Record evidence** with timestamps, search criteria, observed result, and limitations.

## Findings supported by the project report

- Splunk Enterprise was deployed on Ubuntu Server and Splunk Universal Forwarder was configured on Windows.
- Windows Security, Application, System, and PowerShell-related events were collected and searched.
- Failed Windows logons were investigated using Security Event ID 4625.
- Nmap service/version and SYN scans were run from Kali against the Windows endpoint.
- DVWA SQL injection was tested locally on Windows and Apache access-log evidence was searched in Splunk.
- PowerShell Operational Event ID 4104 was used to verify script-block event collection.
- Splunk alerts were configured for failed logins, Nmap reconnaissance/SYN scan, and web SQL injection.
- A Dashboard Studio dashboard named **SOC Security Monitoring Dashboard** was created.

## Interpretation and limitations

- A log event is an observation, not automatically proof of compromise. Correlate related records and account for expected administrative or test activity.
- The DVWA request was documented as local and showed source `::1`; do not attribute it to Kali without supporting evidence.
- Windows Event ID 5156 is dependent on the applicable audit configuration and indicates permitted connections, not necessarily malicious scanning.
- SPL field names and sourcetypes can differ depending on inputs and parsing. Confirm them in your own events.
- Dashboard counts and alert activity depend on the selected time range and saved-search configuration.
- This is an educational virtual lab. The report does not establish production deployment, automated containment, or incident response actions beyond monitoring, detection, investigation, and reporting.

## Evidence handling

When adding screenshots to the repository, use clear filenames and captions. Redact usernames or other personal data when appropriate, passwords, tokens, session IDs, public IPs if sensitive, and any private system information. Prefer screenshots that show the search or alert name, time range, and relevant result fields without exposing secrets.
