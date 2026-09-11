
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

![dig flaws.cloud](../images/01-dig-flaws-cloud.png)

A reverse lookup on one of the IPs confirms it resolves through an **S3 static website hosting endpoint**:

![nslookup S3 endpoint](../images/02-nslookup-s3-endpoint.png)

Browsing the resolved endpoint renders the challenge landing page — confirming public static website hosting is enabled:

![flAWS welcome page](../images/03-welcome-page.png)

With the bucket name known, the full object listing can be pulled down **fully unauthenticated**:

```bash
aws s3 ls s3://flaws.cloud/ --no-sign-request
```

![aws s3 ls bucket listing](../images/04-s3-ls-bucket-listing.png)

The listing exposes `secret-dd02c7c.html` — a file never linked from the site's navigation. "Security by obscurity" fails the moment the bucket itself is listable:

![secret file reveals level 2](../images/05-secret-file-level2-link.png)

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

![level 2 bucket listing](../images/06-level2-bucket-listing.png)

Fetching the disclosed secret file hands over the Level 3 target:

![level 2 secret discloses level 3](../images/07-level2-secret-level3-link.png)

**Fix:** identical to Level 1 — plus adopt an org-wide Service Control Policy (SCP) that denies public bucket ACLs by default, so the pattern can't be reintroduced bucket-by-bucket.

---

## Level 3 — Credentials Leaked via Git History

**Category:** Sensitive Data Exposure — Secrets in Version Control

First attempt: pull `.git` recursively over HTTP with `wget`. Fails — the web server doesn't serve the raw directory listing:

![wget git attempt fails](../images/08-wget-git-attempt-fail.png)

Pivot: Level 3 is *also* backed by S3, so the `.git` object database can be pulled directly out of the bucket instead of through the web server:

```bash
aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ ~/level3loot --no-sign-request
```

![s3 sync pulling git objects](../images/09-s3-sync-git-objects.png)

With a working local repo, `git log` shows two commits — the newest one titled **"Oops, accidentally added something I shouldn't have."** That's the tell:

![git log](../images/10-git-log.png)

`git diff` between the two commits recovers the deleted `access_keys.txt` in full — Git never actually removes history, it just stops tracking a file going forward:

![git diff recovers AWS keys](../images/11-git-diff-access-keys.png)

```diff
-access_key**************
-secret_access_key *********************
```

The recovered key pair is loaded into a dedicated CLI profile and validated:

```bash
aws configure --profile flawslevel3
aws sts get-caller-identity --profile flawslevel3
```

![aws configure profile](../images/12-aws-configure-profile.png)
![sts get-caller-identity](../images/13-sts-get-caller-identity.png)

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

![level 4 login prompt](../images/14-level4-login-prompt.png)

Instead, using the credentials recovered in Level 3, the account's EBS snapshots are enumerated directly via the API. One is tagged `"flaws backup 2017.02.27"` — created right after the box was provisioned, exactly as the level's own hint suggests:

```bash
aws ec2 describe-snapshots --owner-id 975426262029 --profile flawslevel3
```

![describe-snapshots](../images/15-describe-snapshots.png)

A fresh, writable volume is restored from that snapshot into the assessor's own account — no owner interaction required beyond the snapshot being shared:

```bash
aws ec2 create-volume --availability-zone us-west-2a --snapshot-id snap-0b49342abd1bdcb89
```

![create-volume](../images/16-create-volume.png)

The volume is attached to an EC2 instance, mounted, and browsed offline — a complete, forensic copy of the original disk:

![mounted snapshot filesystem](../images/17-mounted-snapshot-ls.png)

Inside `~/`, `setupNginx.sh` still contains the exact provisioning command — with the Basic Auth username/password in **plaintext**:

![setupNginx.sh cleartext creds](../images/18-setupnginx-cleartext-creds.png)

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

![level 5 reached via proxy pivot](../images/19-level5-reached.png)

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
