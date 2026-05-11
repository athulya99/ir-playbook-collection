# Insider Threat Incident Response Playbook

**Severity:** High
**MITRE ATT&CK:** T1078 (Valid Accounts), T1048 (Exfiltration Over Alternative Protocol), T1213 (Data from Information Repositories)
**NIST Phase:** Detection → Containment → Eradication → Recovery

---

## 1. Detection

### Indicators to look for
- Large volume of files accessed or downloaded outside normal working hours
- User accessing data outside their normal role or department
- Unusual USB or removable media usage
- Bulk email sent to personal address or external domain
- DLP alert for sensitive data leaving the organisation
- User accessing systems after resignation or termination notice
- Failed access attempts to systems user does not have authorisation for

### SIEM Queries (Splunk)
```spl
index=dlp_logs action=blocked OR action=alerted user=*
| stats count by user, dest_domain, file_name
| where dest_domain != "yourcompany.com"
| sort -count
```
```spl
index=windows_logs EventCode=4663 _time>=relative_time(now(),"-7d@d")
| stats count by user, Object_Name
| where count > 200
| join user [search index=hr_data status=resigned OR status=terminated]
```

---

## 2. Triage

| Question | Action |
|---|---|
| Is this a current or departing employee? | Check HR records immediately — do not alert the employee |
| What data was accessed or copied? | Review DLP, file access, and email logs |
| Has data already left the organisation? | Check email gateway, proxy, and USB logs |
| Is there a business justification? | Verify with manager — do this discreetly |

**Important:** Handle all insider threat investigations with strict confidentiality. Involve HR and Legal before taking any action that could alert the employee.

---

## 3. Containment

### Immediate
- [ ] **Do not alert the user** — covert monitoring may be required (consult Legal)
- [ ] Engage HR and Legal before any overt action
- [ ] Preserve all logs — place legal hold on email, file access, and DLP records
- [ ] If imminent data loss risk: quietly revoke access to sensitive systems
- [ ] Capture forensic image of the employee's device (with HR/Legal sign-off)

### Short-term
- [ ] Review full access history for the past 30–90 days
- [ ] Identify all data accessed, copied, or transmitted
- [ ] Check for cloud sync tools (OneDrive, Dropbox, Google Drive) activity
- [ ] Review any privileged access usage — check admin logs
- [ ] Coordinate with manager to understand recent behaviour and context

---

## 4. Eradication

- [ ] Revoke all system access upon formal HR decision
- [ ] Disable Active Directory account and invalidate all sessions
- [ ] Recover company devices and wipe after forensic image is taken
- [ ] Change shared credentials or service accounts the user had access to
- [ ] Revoke any API keys, certificates, or tokens issued to the user
- [ ] Review and close any backdoors or accounts the user may have created

---

## 5. Recovery

- [ ] Audit all access granted to the user and verify no residual access remains
- [ ] Notify affected data owners if sensitive data was compromised
- [ ] Assess whether customer/patient data notification is required (GDPR)
- [ ] Review access control policies — apply principle of least privilege
- [ ] Strengthen DLP rules based on exfiltration method used

---

## 6. Post-Incident

- [ ] Complete incident report — document evidence chain carefully (may be needed for legal proceedings)
- [ ] Coordinate with Legal on any disciplinary or law enforcement action
- [ ] Assess GDPR obligations if personal data was involved
- [ ] Conduct access review across all departing and high-risk staff
- [ ] Review onboarding/offboarding procedures and tighten access revocation timelines

---

## References
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [CISA Insider Threat Mitigation Guide](https://www.cisa.gov/insider-threat-mitigation)
- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
