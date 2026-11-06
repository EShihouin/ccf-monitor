# Setup

Every step needed to rebuild this lab from scratch, in order. Commands are for macOS (zsh); adjust for other systems.

Last verified: 2026-11-05

## 1. Accounts and guardrails (browser)

- [x] GitHub account with two-factor authentication
- [x] AWS account on the Free plan, region `us-east-1`
- [x] Root user: MFA enabled, no access keys
- [x] Zero-spend budget with a verified email recipient
- [x] Account alias: `eshihouin-security-lab`
- [x] Admin IAM user `eshihouin-admin`: console access, `AdministratorAccess`, MFA, no access keys
- [ ] Monitor IAM user `ccf-auditor`: no console access, `SecurityAudit` only

## 2. Install tools

```bash
# Homebrew: copy the install command from https://brew.sh, then run the "Next steps" it prints
brew install python git awscli gh
python3 --version; git --version; aws --version; gh --version
```

Output on 2026-11-05:

```
Python 3.15.2
git version 2.56.0
aws-cli/2.39.5 Python/3.15.2 Darwin/24.6.0 source/arm64
gh version 2.103.3 (2026-10-26)
```

Save the tool list for others:

```bash
brew bundle dump
```

## 3. Get the code

```bash
gh auth login            # GitHub.com > HTTPS > web browser
mkdir -p ~/projects && cd ~/projects
gh repo clone EShihouin/ccf-monitor
cd ccf-monitor
```

## 4. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install [PACKAGES]
pip freeze > requirements.txt
```

## 5. Connect to AWS

[Describe how you created the ccf-auditor access key and configured the profile.]

```bash
aws configure --profile ccf
aws sts get-caller-identity --profile ccf
```

Expected: an ARN ending in `user/ccf-auditor`.

## 6. Connect to the GitHub API

- Fine-grained personal access token, repository access: `ccf-monitor` only
- Permissions (read-only): [Administration, Dependabot alerts, Secret scanning alerts, Metadata]
- Stored in: [`.env` (gitignored) / macOS Keychain]

```bash
gh api repos/[YOUR-USERNAME]/ccf-monitor
```

## 7. Repository security settings

- [ ] Dependabot alerts on
- [ ] Secret scanning and push protection on
- [ ] Branch protection on `main`: [settings you chose]

## 8. Run

```bash
python3 monitor.py
open output/dashboard.html
```

## 9. Automation (optional)

- [ ] GitHub OIDC identity provider added in IAM
- [ ] Role `[ROLE-NAME]` with `SecurityAudit`, trust limited to `repo:[YOUR-USERNAME]/ccf-monitor:ref:refs/heads/main`
- [ ] Workflow `.github/workflows/monitor.yml` runs on a schedule and on demand
- [ ] GitHub token stored as repo secret `[SECRET-NAME]`

## 10. Teardown

- [ ] Delete demo resources: [list]
- [ ] Delete or rotate `ccf-auditor` access keys
- [ ] Keep root MFA and the budget

## Troubleshooting

| Problem | Fix |
| --- | --- |
| [e.g., `brew: command not found`] | [Run the "Next steps" commands Homebrew printed] |
| [ ] | [ ] |
