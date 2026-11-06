# ccf-monitor

A mini Common Control Framework (CCF) that tests security controls against **live evidence** from an AWS account, a GitHub repository and an AI agent configuration, then reports pass, at risk, fail or error per control and readiness per framework.

> Personal lab project built to practice second-line control assurance: confirming controls are designed, implemented and operating, not just documented.

## What it does

- **Catalog:** [NUMBER] controls anchored to NIST SP 800-53 Rev. 5, mapped to ISO/IEC 27001:2022 and SOC 2 Trust Services Criteria (`controls/catalog.csv`)
- **Collect:** pulls evidence from AWS and GitHub APIs and saves timestamped snapshots (`evidence/`)
- **Evaluate:** tests each control against its evidence using the full population, failing closed on errors (`checks/`)
- **Report:** writes `output/results.json`, `output/results.csv` and `output/dashboard.html`
- **Automate:** [runs daily via GitHub Actions using OIDC, with no stored AWS keys | planned next step]

## Controls

| ID | Control | NIST 800-53 | ISO 27001 | SOC 2 | Evidence source | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CCF-01 | [MFA for every human user] | [IA-2(1), IA-2(2)] | [ ] | [ ] | [IAM credential report] | [built / planned] |
| CCF-02 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-03 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-04 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-05 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-06 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-07 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-08 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| CCF-09 | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |

Full control statements, owners, frequencies and pass rules are in `controls/catalog.csv`.

## How it works

```
catalog.csv  ->  collect (API)  ->  evidence/*.json  ->  evaluate  ->  results  ->  dashboard
                                                                           |
                                         findings feed back into control design
```

**Design principles**

- **Collect and evaluate are separate.** Evidence is saved before it's judged, so results are reproducible and auditable.
- **Fail closed.** If evidence can't be collected, the status is `error`, never `pass`.
- **Full population.** Every user, bucket and alert is tested, not a sample.
- **Least privilege.** The monitor's AWS identity has only the `SecurityAudit` managed policy (read-only).

Design decisions and trade-offs are logged in [`docs/DECISIONS.md`](docs/DECISIONS.md).

## Prerequisites

| Tool | Minimum version | Tested with |
| --- | --- | --- |
| Python | 3.12 | 3.15.2 |
| Git | 2.40 | 2.56.0 |
| AWS CLI | v2 | 2.39.5 |
| GitHub CLI (optional) | 2.40 | 2.103.3|

Accounts: an AWS account and a GitHub account. Mac users can install tools with `brew bundle` (see `Brewfile`).

## Quick start

```bash
git clone https://github.com/EShihouin/ccf-monitor.git
cd ccf-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# configure AWS and GitHub access: see SETUP.md
python3 monitor.py
open output/dashboard.html
```

Full setup, including the AWS identity and GitHub token, is in [`SETUP.md`](SETUP.md).

## Repository layout

```
controls/            control catalog
checks/              collect + evaluate functions, one file per system
ai/                  sample AI agent config and approved tools list
demo-app/            deliberately outdated dependencies for the vulnerability check (never installed)
evidence/            raw evidence snapshots (gitignored)
output/              results and dashboard (gitignored)
.github/workflows/   scheduled automation
monitor.py           entry point
```

## Security notes

- No credentials, tokens, account IDs or real usernames are committed. `evidence/`, `output/`, `.venv/` and `.env` are gitignored.
- The AWS identity is read-only (`SecurityAudit`). The GitHub token is fine-grained, scoped to this repo, read-only.
- [CI uses GitHub OIDC with a role restricted to this repo's `main` branch.]

## Limitations and next steps

- [e.g., Single AWS account and single repo; no exception tracking yet]
- [e.g., Free plan account, so IAM users are used locally instead of IAM Identity Center]
- [Next: exception register with expiry dates]
- [Next: export results to a GRC platform]

## License

MIT. See [`LICENSE`](LICENSE).
