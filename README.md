# flAWS.cloud Walkthrough

<img width="1271" height="368" alt="Flaws 5" src="https://github.com/user-attachments/assets/9c739f4c-b1d2-47c6-a309-8a6d06ef9fd9" />

<img width="1270" height="628" alt="level4 7" src="https://github.com/user-attachments/assets/274228c3-f339-4ed6-87a6-f5167b60841e" />

![License](https://img.shields.io/badge/Use-Educational-lightgrey)

A hands-on walkthrough of [flAWS.cloud](http://flaws.cloud) — Scott Piper's (Summit Route) public AWS security training challenge. Five levels, five real-world AWS misconfiguration classes: public S3 buckets, credentials leaked via Git history, and a publicly shared EBS snapshot.

> flaws.cloud is an intentionally vulnerable, publicly authorized training target. Everything here stayed within that scope.

## Findings at a Glance

| Level | Issue | Severity |
|---|---|---|
| 1 | Public S3 bucket — open `ListBucket` | High |
| 2 | Same open-ACL pattern, second bucket | High |
| 3 | AWS keys recovered from public `.git` history | **Critical** |
| 4 | Public EBS snapshot → cleartext creds | **Critical** |
| 5 | SSRF-style proxy trust between hosts | High |

**Tools used:** `dig`, `nslookup`, AWS CLI, `git`, `wget`, Kali Linux

## Full Write-Up

Commands, screenshots, root cause analysis, and remediation for every level are in:

**[docs/WALKTHROUGH.md](docs/WALKTHROUGH.md)**

Formal report versions (executive summary, technical detail, remediation plan) are also available as Word documents in [`docs/`](docs).

## Takeaway

No zero-days — every step here uses public tooling against well-known misconfiguration classes. Individually "minor" issues chain fast: one open bucket → leaked keys → account-wide access → server secrets. These patterns remain top real-world causes of cloud breaches.

---

**Author:** George Munene Ng'ang'a · Cybersecurity & Cloud Security
**Target:** [flaws.cloud](http://flaws.cloud) by Scott Piper / Summit Route
