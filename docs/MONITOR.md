# How the monitor works

`monitor.py` tests 11 controls against live evidence and writes a dashboard.

## Run it

```bash
cd ~/projects/ccf-monitor
source .venv/bin/activate
python3 -m unittest          # 21 tests: each check catches a planted failure
python3 monitor.py           # collect fresh evidence, then evaluate
open output/dashboard.html
```

Re-judge saved evidence without calling any API: `python3 monitor.py --offline`

## The flow

```
controls/catalog.csv ──> collect (read-only API calls) ──> evidence/*.json ──> evaluate ──> output/
                         AWS: ccf profile                  timestamped,         pass / at risk /
                         GitHub: token in .env             who pulled it        fail / error
                         AI: ai/*.json
                         Scanners: trivy_*.json, gitleaks_*.json (you run these)
```

## The controls

| ID | Checks | Evidence |
| --- | --- | --- |
| CCF-01 | Every console user has MFA | IAM credential report |
| CCF-02 | Root has MFA, no keys, no recent use | Credential report, root row |
| CCF-03 | Access keys under 90 days old and in use | Credential report, key columns |
| CCF-04 | A multi-region CloudTrail trail is logging | CloudTrail API |
| CCF-05 | S3 Block Public Access and encryption | S3 and S3 Control APIs |
| CCF-06 | `main` requires an approved pull request | GitHub branch protection and rulesets |
| CCF-07 | Dependabot alerts fixed within SLA (15/30/90 days) | Dependabot alerts API |
| CCF-08 | No open secret scanning alerts | Secret scanning API (secret values never saved) |
| CCF-09 | AI agent: named owner, approved tools only, write tools gated | `ai/agent_config.json` vs `ai/approved_tools.json` |
| CCF-10 | No critical or high CVEs | Trivy JSON you saved in `evidence/` |
| CCF-11 | No secrets in code | gitleaks JSON you saved in `evidence/` |

## Design decisions (and why)

- **Collect, then evaluate.** Evidence is saved before it's judged, so results can be reproduced and audited, and the logic can be tested offline.
- **Fail closed.** Missing evidence, an access error or a crashed check is `error`, never `pass`.
- **Full population.** The credential report covers every IAM user, not a sample.
- **Read-only access.** AWS uses `ccf-auditor` (SecurityAudit + ViewOnlyAccess). GitHub uses a fine-grained, read-only token for one repo that expires in 30 days.
- **Test the tests.** `tests/` plants a failure for every check and confirms it's caught.
- **No secrets in evidence.** Secret scanning and gitleaks findings keep only type, file and line.

## Fix-it demo ideas

- CCF-09: add an `owner`, set `requires_human_approval: true` on `crm.update_case`, and remove `email.send_customer` (or approve it). Re-run and it passes.
- CCF-06: protect `main` (Settings → Branches → require a pull request with 1 approval). Re-run and it passes.
- CCF-01: delete `demo-contractor` or give it MFA. Re-run and it passes.
