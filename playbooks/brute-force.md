# Brute Force / Credential Attack Incident Response Playbook

**Severity:** Medium → High (escalate if successful login confirmed)
**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts), T1556 (Modify Authentication Process)
**NIST Phase:** Detection → Containment → Eradication → Recovery

---

## 1. Detection

### Indicators to look for
- Multiple failed login attempts against one or many accounts (Event ID 4625)
- Account lockouts across multiple users in a short timeframe (Event ID 4740)
- Login attempts from unusual geographic locations or IP ranges
- Successful login immediately following a series of failures
- Password spray pattern — one password tried across many accounts
- RDP or VPN brute force alerts from firewall/IDS

### SIEM Queries (Splunk)
```spl
index=windows_logs EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| sort -count
```
```spl
index=windows_logs EventCode=4740
| stats count by TargetUserName, src_ip
| sort -_time
```
```spl
index=windows_logs EventCode=4625
| stats dc(TargetUserName) as unique_users by src_ip
| where unique_users > 5
```

---

## 2. Triage

| Question | Action |
|---|---|
| Was any login successful after the failures? | Check Event ID 4624 within 30 mins of the failures — critical escalation trigger |
| Is this a password spray or brute force? | Spray = many users, few attempts each. Brute force = one user, many attempts |
| What is the source IP? | Geolocate — internal vs external. Check threat intel feeds |
| Which accounts were targeted? | Check if any are admin or privileged accounts — escalate immediately |

---

## 3. Containment

### Immediate
- [ ] Block the attacking IP(s) at the firewall
- [ ] Lock any accounts with confirmed successful compromise
- [ ] Enable account lockout policy if not already active (GPO)
- [ ] If RDP-based: restrict RDP access to VPN only or specific IP ranges
- [ ] Alert IT/security team of ongoing attack

### Short-term
- [ ] Force password reset on all targeted accounts
- [ ] Enable or enforce MFA on all targeted accounts
- [ ] Review firewall logs for additional attacking IPs — block entire subnet if needed
- [ ] Check for any post-compromise activity (new accounts created, files accessed)
- [ ] Review exposed services — is RDP, SSH, or OWA unnecessarily public-facing?

---

## 4. Eradication

- [ ] Confirm attacking source is fully blocked
- [ ] Audit all accounts for unauthorised changes (new forwarding rules, new admin rights)
- [ ] Remove any persistence left by attacker if compromise confirmed
- [ ] Review and tighten account lockout and password policies
- [ ] Disable or move any exposed services behind VPN

---

## 5. Recovery

- [ ] Restore any lockout accounts once attack is confirmed stopped
- [ ] Issue new credentials to all affected accounts
- [ ] Confirm MFA is active on all restored accounts
- [ ] Monitor affected accounts closely for 48 hours

---

## 6. Post-Incident

- [ ] Document attacking IPs and add to blocklist/threat intel
- [ ] Review and update SIEM alerting thresholds for failed logins
- [ ] Assess whether account lockout policy is appropriately configured
- [ ] Recommend MFA rollout if not already organisation-wide
- [ ] Complete incident report

---

## References
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [Microsoft — Investigate and remediate brute force attacks](https://learn.microsoft.com/en-us/defender-for-identity/compromised-credentials-alerts)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
