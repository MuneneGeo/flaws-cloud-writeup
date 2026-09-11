
# flAWS.cloud — Full Technical Walkthrough

[← Back to README](../README.md)

Detailed, level-by-level breakdown with commands, screenshots, root cause, and remediation for each finding.

## Table of Contents

- [Level 1 — Public S3 Bucket Enumeration](#level-1--public-s3-bucket-enumeration)
- [Level 2 — Repeated Public Bucket ACL](#level-2--repeated-public-bucket-acl)
- [Level 3 — Credentials Leaked via Git History](#level-3--credentials-leaked-via-git-history)
- [Level 4 — Public EBS Snapshot → Cleartext Credentials](#level-4--public-ebs-snapshot--cleartext-credentials)
- [Level 5 — SSRF / Proxy Trust Pivot](#level-5--ssrf--proxy-trust-pivot)
- [Cross-Cutting Root Causes](#cross-cutting-root-causes)
- [Remediation Summary](#remediation-summary)

---

## Level 1 — Public S3 Bucket Enumeration

**Category:** Broken Access Control (S3 Bucket ACL/Policy)

Recon starts with plain DNS. `dig flaws.cloud` returns eight A records instead of one — a strong signal the domain sits behind a highly-available AWS service, not a single server.

<img width="975" height="585" alt="flaws 1" src="https://github.com/user-attachments/assets/f0b20fdb-fdff-414b-b6f1-5e75d639fc24" />


A reverse lookup on one of the IPs confirms it resolves through an **S3 static website hosting endpoint**:

<img width="743" height="134" alt="Flaws 2" src="https://github.com/user-attachments/assets/d0ae13f4-2182-481e-8940-8fb8d3803f51" />


Browsing the resolved endpoint renders the challenge landing page — confirming public static website hosting is enabled:

<img width="1263" height="720" alt="Flaws 3" src="https://github.com/user-attachments/assets/1c4cf09a-71e8-452a-81e0-389d6ce7b3c3" />


With the bucket name known, the full object listing can be pulled down **fully unauthenticated**:

```bash
aws s3 ls s3://flaws.cloud/ --no-sign-request
```

<img width="763" height="217" alt="Flaws 4" src="https://github.com/user-attachments/assets/65807203-3ef8-49b6-8f36-fe8692a53984" />


The listing exposes `secret-dd02c7c.html` — a file never linked from the site's navigation. "Security by obscurity" fails the moment the bucket itself is listable:


**Root cause:** the bucket policy/ACL grants `s3:ListBucket` and `s3:GetObject` to `Principal: *`. Public *list* access is the real problem — it makes every "hidden" object trivially discoverable.

**Fix:**
- Remove public `ListBucket`; scope `GetObject` to specific object ARNs only.
- Enable **S3 Block Public Access** at the account and bucket level.
- Serve public content through CloudFront + Origin Access Control instead of the raw S3 website endpoint.

---

## Level 2 — Repeated Public Bucket ACL

Same pattern, second bucket. Listing is open again:

```bash
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/
```

<img width="763" height="217" alt="Flaws 4" src="https://github.com/user-attachments/assets/1de7b282-63a7-4c40-b9fc-be484355c793" />

Fetching the disclosed secret file hands over the Level 3 target:

<img width="1269" height="381" alt="Flaws 7 - Copy" src="https://github.com/user-attachments/assets/a72afd0e-5738-4b33-b0c7-c7be19741672" />


**Fix:** identical to Level 1 — plus adopt an org-wide Service Control Policy (SCP) that denies public bucket ACLs by default, so the pattern can't be reintroduced bucket-by-bucket.

---

## Level 3 — Credentials Leaked via Git History

**Category:** Sensitive Data Exposure — Secrets in Version Control

First attempt: pull `.git` recursively over HTTP with `wget`. Fails — the web server doesn't serve the raw directory listing:

<img width="1270" height="400" alt="Flaws 08" src="https://github.com/user-attachments/assets/9202861f-0e05-4ec0-bfd7-5b78c390bfbe" />


Pivot: Level 3 is *also* backed by S3, so the `.git` object database can be pulled directly out of the bucket instead of through the web server:

```bash
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ ~/level3loot --no-sign-request
```

<img width="1260" height="660" alt="flaws 8" src="https://github.com/user-attachments/assets/dbaa16e3-ca7a-471e-a2da-00285747fbc4" />


With a working local repo, `git log` shows two commits — the newest one titled **"Oops, accidentally added something I shouldn't have."** That's the tell:

<img width="986" height="298" alt="Flaws 9" src="https://github.com/user-attachments/assets/0e0479ca-65e3-455f-99f3-7dc14d948fa4" />

`git diff` between the two commits recovers the deleted `access_keys.txt` in full — Git never actually removes history, it just stops tracking a file going forward:

<img width="1275" height="577" alt="Flaws 10" src="https://github.com/user-attachments/assets/2e656245-7a53-449c-a5bf-d12b122e5160" />


```diff
-access_key**************
-secret_access_key *********************
```

The recovered key pair is loaded into a dedicated CLI profile and validated:

```bash
aws configure --profile flawslevel3
aws sts get-caller-identity --profile flawslevel3
```

<img width="1013" height="181" alt="Flaws 12" src="https://github.com/user-attachments/assets/989d9f18-4a9b-40fc-8ee3-a414c1532519" />


Confirmed: `arn:aws:iam::975426262029:user/backup` — a live, working IAM identity, used for every subsequent level.

**Root cause:** credentials were committed, then only *deleted* (not rotated) in a later commit — and the `.git` directory itself lived inside a public bucket, keeping the entire history retrievable forever.

**Fix:**
- Rotate/deactivate any key that has *ever* touched version control — deletion in a later commit does not remove it from history.
- Never store `.git` directories in public buckets; use access-controlled Git hosting.
- Add pre-commit secret scanning (`gitleaks`, `truffleHog`, GitHub push protection).
- Prefer short-lived credentials (IAM roles / STS AssumeRole / SSO) over long-lived access keys.

---

## Level 4 — Public EBS Snapshot → Cleartext Credentials

**Category:** Sensitive Data Exposure — Backup/Snapshot Misconfiguration

Level 4 is an EC2-hosted site behind HTTP Basic Auth — not something to brute-force:

<img width="1261" height="680" alt="level 4 1" src="https://github.com/user-attachments/assets/fcb38685-7e2e-4c5f-94d4-a56d09ebd9fd" />


Instead, using the credentials recovered in Level 3, the account's EBS snapshots are enumerated directly via the API. One is tagged `"flaws backup 2017.02.27"` — created right after the box was provisioned, exactly as the level's own hint suggests:

```bash
aws ec2 describe-snapshots --owner-id 975426262029 --profile flawslevel3
```


<img width="1106" height="611" alt="level4 3" src="https://github.com/user-attachments/assets/edcaad75-3468-4063-ae00-c2874e0116e7" />

A fresh, writable volume is restored from that snapshot into the assessor's own account — no owner interaction required beyond the snapshot being shared:

```bash
aws ec2 create-volume --availability-zone us-west-2a --snapshot-id snap-0b49342abd1bdcb89
```

<img width="1155" height="351" alt="level4 4" src="https://github.com/user-attachments/assets/17719eb0-80e7-44b3-b708-88bacc063988" />


The volume is attached to an EC2 instance, mounted, and browsed offline — a complete, forensic copy of the original disk:

<img width="1267" height="697" alt="level 4 5" src="https://github.com/user-attachments/assets/db30f1db-a1fc-4a91-b789-f7d4d7cab5b5" />


Inside `~/`, `setupNginx.sh` still contains the exact provisioning command — with the Basic Auth username/password in **plaintext**:
<img width="1069" height="686" alt="level 4 6" src="https://github.com/user-attachments/assets/7c5e6ff0-8eb3-4b96-9041-edef5bbba835" />

```bash
htpasswd -b /etc/nginx/.htpasswd flaws nCP8xigdjpJyiXgJ7nJu7rw5Ro68iE8M
```

That credential unlocks the Level 4 login prompt.

**Root cause:** the snapshot's sharing permissions allowed cross-account access, the volume wasn't encrypted, and the provisioning script hard-coded a plaintext password on disk instead of using a managed secrets store.

**Fix:**
- Never share EBS snapshots/AMIs publicly or cross-account without explicit, restricted resource policies.
- Enable **default EBS encryption** account-wide (`aws ec2 enable-ebs-encryption-by-default`).
- Never write secrets into provisioning scripts or user-data — use AWS Secrets Manager / SSM Parameter Store (SecureString).
- Continuously audit for public snapshot exposure with AWS Config (`ebs-snapshot-public-restorable-check`).

---

## Level 5 — SSRF / Proxy Trust Pivot

**Category:** Server-Side Request Forgery / Excessive Trust Between Hosts

Authenticating into the Level 4 host with the recovered credentials leads straight into Level 5 — served through the Level 4 instance acting as a proxy into a separate resource:

<img width="1270" height="397" alt="level 4 8" src="https://github.com/user-attachments/assets/0dcf3a5c-f997-4639-8a4a-e2ab418b434b" />


**Root cause:** the Level 4 server proxies requests onward without validating the destination or the caller's authorization — a single compromised front-end host becomes a pivot point deeper into the environment.

**Fix:**
- Enforce **IMDSv2** (token-required) fleet-wide to close SSRF → credential-theft paths.
- Apply strict allow-lists for any server-side proxy/forwarding functionality.
- Segment networks so a compromised public host can't reach sensitive internal endpoints by default.

---

## Cross-Cutting Root Causes

Three themes explain every finding in this walkthrough:

1. **Overly permissive S3 bucket permissions** (Levels 1–3) — public `ListBucket` is the recurring single point of failure.
2. **Secrets management failures** (Levels 3–4) — plaintext credentials, in the wrong place, never rotated after exposure.
3. **Weak backup/snapshot governance** (Level 4) — a snapshot is a full offline copy of a disk and needs the same access rigor as the live system.

---

## Remediation Summary

| Priority | Action | Timeframe |
|---|---|---|
| 1 | Enable S3 Block Public Access account-wide; audit all buckets for public list/read | Immediate (0–7 days) |
| 2 | Rotate any credential ever committed to version control; deploy secret scanning | Immediate (0–7 days) |
| 3 | Audit all EBS snapshots/AMIs for public sharing; enable default encryption | Short-term (2–4 weeks) |
| 4 | Move hard-coded secrets to Secrets Manager / SSM Parameter Store | Short-term (2–4 weeks) |
| 5 | Enforce IMDSv2 fleet-wide; review server-side proxy functionality for SSRF | Medium-term (1–2 months) |
| 6 | Deploy continuous CSPM (IAM Access Analyzer, AWS Config, GuardDuty) | Ongoing |

---

[← Back to README](../README.md)
