# Phishing Incident Response Playbook

**Severity:** High
**MITRE ATT&CK:** T1566 (Phishing), T1204 (User Execution), T1078 (Valid Accounts)
**NIST Phase:** Detection → Containment → Eradication → Recovery

---

## 1. Detection

### Indicators to look for
- User reports a suspicious email with unexpected attachments or links
- Email gateway alert for blocked or quarantined message
- SIEM alert: mass email received from external domain
- Unusual login from new location/device shortly after email received
- Antivirus alert on attachment execution

### SIEM Queries (Splunk)
```spl
index=email_logs subject="*invoice*" OR subject="*urgent*" OR subject="*password*"
| stats count by src_user, subject, sender_domain
| where count > 1
```
```spl
index=windows_logs EventCode=4624 LogonType=3
| join user [search index=email_logs action=clicked]
| table _time, user, src_ip, dest
```

---

## 2. Triage

| Question | Action |
|---|---|
| Did the user click the link or open the attachment? | Check proxy/web logs and endpoint AV logs |
| Were credentials entered on a fake site? | Check for password reset events in Active Directory |
| Did the email reach multiple users? | Search mail logs for same sender/subject |
| Was any file executed? | Check Sysmon/EDR for process creation events |

**Severity escalation triggers:**
- Credentials confirmed compromised → escalate to Critical
- Attachment executed → escalate to Critical
- More than 10 users received same email → notify Security Manager

---

## 3. Containment

### Immediate (0–1 hour)
- [ ] Quarantine the malicious email from all mailboxes using admin console (M365: Content Search → Purge)
- [ ] Block sender domain and IP at email gateway
- [ ] Disable the affected user account in Active Directory if credentials are compromised
- [ ] Isolate endpoint from network if attachment was executed
- [ ] Block malicious URLs at web proxy/firewall

### Short-term (1–24 hours)
- [ ] Reset affected user credentials and force MFA re-registration
- [ ] Review mail flow rules for similar patterns
- [ ] Search for lateral movement from affected account (failed logins, unusual access)
- [ ] Preserve email headers and attachment samples for forensic analysis

---

## 4. Eradication

- [ ] Confirm all copies of the email removed from all mailboxes
- [ ] Remove any malicious files from endpoints (coordinate with AV/EDR)
- [ ] Revoke all active sessions for compromised account
- [ ] Remove any persistence mechanisms found (scheduled tasks, registry run keys)
- [ ] Verify no forwarding rules were created on the compromised mailbox

---

## 5. Recovery

- [ ] Re-enable user account with new credentials
- [ ] Confirm MFA is active and working
- [ ] Monitor account activity closely for 72 hours post-recovery
- [ ] Restore any files from backup if needed
- [ ] Confirm endpoint is clean via AV full scan before reconnecting

---

## 6. Post-Incident

- [ ] Complete incident report using [Incident Report Template](../templates/incident-report-template.md)
- [ ] Document IOCs (sender IP, domain, URL, file hash) in threat intel platform
- [ ] Update email gateway blocklist
- [ ] Schedule phishing awareness reminder for affected department
- [ ] Review and tune SIEM detection rules based on this incident

---

## References
- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)
- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [Microsoft - Respond to a compromised email account](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account)
