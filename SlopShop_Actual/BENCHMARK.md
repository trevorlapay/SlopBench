# SlopShop_Actual — real post-cutoff CVE bench (evaluator-only)

> Evaluator-only. Remove `BENCHMARK.md`, `tools/`, `corpus/`, `provenance/`,
> `build/` before pointing a scanner at this directory. What remains —
> `README.md`, `services/`, `infra/` — is an ordinary polyglot app.

The answer key is `VulnerabilityKeys/SlopShop_Actual.vulnerability_key.json`.

Every finding is a **real, publicly-disclosed CVE** whose advisory was published
**after 2025-12-01**. Each component under `services/*/` is the **verbatim upstream
source at the pre-fix commit, together with its surrounding module** so the
source->sink flow is present in-repo (an agent must read across files).

- Scored findings: **150**
- Ground-truth line = the re-derived real sink line (not the fix commit's
  incidental hunk line).

## Out of scope (dropped)

Dropped for one of two reasons: **pre-cutoff-fix-commit** (the fix landed on or
before 2025-12-01 by committer date, so the vuln was public pre-cutoff despite a
later OSV/CVE timestamp) or **no-code-sink** (the fix touched only config/imports,
or the defect is purely out-of-repo). Not scored:

- CVE-2025-68436 (no-code-sink (import/comment/config-only fix)): Craft CMS vulnerable to potential information disclosure via unchecked asset rel
- CVE-2023-7333 (pre-cutoff-fix-commit (2023-10-30)): records-mover Injection vulnerability
- CVE-2026-28802 (pre-cutoff-fix-commit (2025-04-23)): Authlib: Setting `alg: none` and a blank signature appears to bypass signature v
- CVE-2025-65105 (pre-cutoff-fix-commit (2025-11-19)): Apptainer ineffectively applies selinux and apparmor --security options
- CVE-2026-25628 (pre-cutoff-fix-commit (2025-11-14)): qdrant has arbitrary file write via `/logger` endpoint
- CVE-2026-40034 (pre-cutoff-fix-commit (2023-08-06)): gitoxide: CommandForbiddenInModulesConfiguration Bypass in gix_submodule::File::
- CVE-2025-14273 (pre-cutoff-fix-commit (2025-11-19)): Mattermost with Jira plugin enabled has Incorrect Implementation of Authenticati
- CVE-2025-13327 (pre-cutoff-fix-commit (2025-10-29)): uv has ZIP payload obfuscation through parsing differentials
- CVE-2020-36962 (pre-cutoff-fix-commit (2020-10-29)): Tendenci is Vulnerable to CSV Formula Injection through its Contact Form Message
- CVE-2025-53960 (pre-cutoff-fix-commit (2025-10-26)): Apache StreamPark: Use the user’s password as the secret key Vulnerability
- GHSA-h4hf-v6w5-897x (no-code-sink (import/comment/config-only fix)): Poweradmin: API user-update endpoint leads to a non-admin reset any user's passw
- CVE-2025-54947 (pre-cutoff-fix-commit (2025-10-26)): Apache StreamPark has a hard-coded encryption key
- CVE-2026-71851 (pre-cutoff-fix-commit (2020-02-10)): crypto-js: Insufficient Entropy in Cryptographic Secret Generation via Vulnerabl
- CVE-2026-40869 (pre-cutoff-fix-commit (2019-06-17)): Decidim amendments can be accepted or rejected by anyone
