# Ransomware Incident Response Playbook

**Severity:** Critical
**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1562 (Impair Defenses)
**NIST Phase:** Detection → Containment → Eradication → Recovery

---

## 1. Detection

### Indicators to look for
- User reports files have strange extensions or cannot be opened
- Ransom note file present on desktop or shared drives (e.g. `READ_ME.txt`, `DECRYPT_FILES.html`)
- SIEM alert: mass file rename or extension change events
- AV/EDR alert for known ransomware signature
- Sudden spike in file write operations on file server
- Volume Shadow Copy deletion events (Event ID 524, vssadmin commands)

### SIEM Queries (Splunk)
```spl
index=windows_logs EventCode=4663 Object_Type=File
| stats count by user, Object_Name
| where count > 500
| sort -count
```
```spl
index=windows_logs (CommandLine="*vssadmin*delete*" OR CommandLine="*wbadmin*delete*")
| table _time, host, user, CommandLine
```

---

## 2. Triage

| Question | Action |
|---|---|
| Is encryption still in progress? | Check CPU/disk I/O on affected hosts — isolate immediately |
| Which systems are affected? | Check file server logs and endpoint alerts across environment |
| Are backups intact? | Verify backup status — check if backup agent was targeted |
| Has data been exfiltrated? | Check outbound network traffic in the 24–72hrs before encryption |

**Severity escalation triggers:**
- Any system affected → immediate escalation to Critical
- Backups compromised → notify senior management and legal
- Patient/customer data involved → activate GDPR breach notification process

---

## 3. Containment

### Immediate (0–30 minutes) — SPEED IS CRITICAL
- [ ] **Isolate all affected endpoints** — disconnect from network (physically or via EDR network isolation)
- [ ] **Disable affected user accounts** in Active Directory
- [ ] **Isolate affected network segments** at switch/firewall level
- [ ] **Do NOT power off machines** — preserve memory for forensic analysis (unless encryption is actively running)
- [ ] **Notify senior management and legal** immediately
- [ ] Alert other staff — do not open suspicious files

### Short-term (30 min–4 hours)
- [ ] Identify patient zero (first infected host) from SIEM/EDR timeline
- [ ] Determine attack vector (phishing? RDP brute force? Vulnerable service?)
- [ ] Preserve memory dumps from affected systems using Volatility or EDR
- [ ] Check for lateral movement — review authentication logs across the environment
- [ ] Block ransomware C2 domains/IPs at firewall

---

## 4. Eradication

- [ ] Confirm all affected endpoints identified
- [ ] Wipe and rebuild affected endpoints — do not trust cleaning alone for ransomware
- [ ] Remove any persistence mechanisms (scheduled tasks, registry keys, rogue admin accounts)
- [ ] Patch the initial attack vector before reconnecting systems
- [ ] Rotate all credentials — assume all passwords on affected systems are compromised
- [ ] Re-image from known-good baseline

---

## 5. Recovery

- [ ] Restore data from clean, pre-infection backups — verify backup integrity before restore
- [ ] Confirm no encryption or ransomware artifacts remain before reconnecting
- [ ] Reconnect systems in stages — monitor closely for re-infection
- [ ] Test all restored data for integrity
- [ ] Enforce MFA across all accounts before returning to full operation
- [ ] Monitor environment continuously for 2 weeks post-recovery

---

## 6. Post-Incident

- [ ] Complete incident report — include full timeline, affected systems, data at risk
- [ ] Assess GDPR notification obligation (72-hour window from discovery)
- [ ] Document all IOCs and share with threat intel platforms (if appropriate)
- [ ] Conduct lessons-learned session with all stakeholders
- [ ] Review backup strategy — air-gapped or immutable backups recommended
- [ ] Review and update detection rules for similar ransomware families

---

## Do Not
- ❌ Do not pay the ransom without legal and management authorisation
- ❌ Do not attempt to decrypt files yourself without expert guidance
- ❌ Do not reconnect isolated systems before full eradication is confirmed
- ❌ Do not delete the ransom note — it is evidence

---

## References
- [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
