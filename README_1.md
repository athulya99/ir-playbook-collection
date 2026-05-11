# IR Playbook Collection

A structured library of incident response playbooks for common attack scenarios, built for SOC analysts and security operations teams. Each playbook follows the **NIST SP 800-61** incident response lifecycle and maps to **MITRE ATT&CK** techniques.

## Structure

```
ir-playbook-collection/
├── playbooks/
│   ├── phishing.md
│   ├── ransomware.md
│   ├── insider-threat.md
│   ├── brute-force.md
│   └── malware-infection.md
├── templates/
│   └── incident-report-template.md
├── references/
│   └── escalation-matrix.md
└── README.md
```

## Playbooks

| Incident Type | Severity | MITRE Tactics |
|---|---|---|
| [Phishing](playbooks/phishing.md) | High | Initial Access, Execution |
| [Ransomware](playbooks/ransomware.md) | Critical | Impact, Exfiltration |
| [Insider Threat](playbooks/insider-threat.md) | High | Collection, Exfiltration |
| [Brute Force / Credential Attack](playbooks/brute-force.md) | Medium | Credential Access |
| [Malware Infection](playbooks/malware-infection.md) | High | Execution, Persistence |

## Frameworks Used

- **NIST SP 800-61** — Computer Security Incident Handling Guide
- **MITRE ATT&CK** — Adversarial tactics and techniques mapping
- **ISO/IEC 27035** — Information security incident management

## How to Use

Each playbook follows this structure:
1. **Detection** — How to identify the incident
2. **Triage** — Initial severity assessment
3. **Containment** — Short and long-term containment steps
4. **Eradication** — Remove the threat from the environment
5. **Recovery** — Restore systems safely
6. **Post-Incident** — Lessons learned and documentation

## Author

**Athulya Preetha Subhash**
Data Security Specialist | MSc Cybersecurity
Dublin, Ireland
[LinkedIn](https://www.linkedin.com/in/athulya-subhash-11106b149/)
