# Escalation Matrix

Use this reference during any active incident to determine who to notify and when.

---

## Severity Definitions

| Severity | Definition | Examples |
|---|---|---|
| **Critical** | Major business impact, data breach confirmed or likely, systems down | Ransomware, confirmed data exfiltration, full system compromise |
| **High** | Significant risk, active threat, potential data exposure | Phishing with credential compromise, malware spreading, insider data theft |
| **Medium** | Contained risk, no confirmed data loss, threat partially active | Brute force (no success), suspicious activity under investigation |
| **Low** | Minimal risk, isolated event, no confirmed impact | Blocked phishing email, single failed login, AV detection (quarantined) |

---

## Escalation Contacts

| Role | When to Contact | Timeframe |
|---|---|---|
| **Security Manager** | All High and Critical incidents | Within 1 hour of detection |
| **IT Manager** | Any incident requiring system isolation or rebuild | Within 1 hour |
| **HR** | Any insider threat investigation | Before any overt action |
| **Legal / DPO** | Any potential data breach, GDPR obligation | Within 2 hours of Critical incident |
| **Senior Management / CEO** | Critical incidents with business or reputational impact | Within 2 hours |
| **Gardaí / Law Enforcement** | Criminal activity confirmed (ransomware, insider theft, fraud) | After legal consultation |
| **Data Protection Commission** | Personal data breach confirmed | Within 72 hours of discovery (GDPR Article 33) |

---

## GDPR Breach Notification Quick Reference

Under **GDPR Article 33**, a personal data breach must be reported to the supervisory authority (Data Protection Commission in Ireland) **within 72 hours** of becoming aware, unless the breach is unlikely to result in a risk to individuals' rights and freedoms.

Under **GDPR Article 34**, if the breach is likely to result in a **high risk** to individuals, those individuals must also be notified **without undue delay**.

**DPC breach notification portal:** [https://www.dataprotection.ie/en/organisations/data-breach-notification](https://www.dataprotection.ie/en/organisations/data-breach-notification)

---

## Communication Rules During an Incident

- All incident communications go through the designated incident channel — not personal email or messaging apps
- Do not discuss incident details publicly or on social media
- All external communications (press, affected individuals) require sign-off from Legal and Senior Management
- Preserve all logs and communications — these may be required as evidence

---

_Template maintained by Athulya Preetha Subhash — [ir-playbook-collection](https://github.com/athulya99/ir-playbook-collection)_
