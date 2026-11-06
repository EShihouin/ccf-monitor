# Design decisions

A short record of why the lab is built the way it is. Each entry: what I decided, what I considered, and the trade-off. Newest first.

This file is the best interview prep in the repo: every entry is an answer to "why did you do it that way?"

---

## [NUMBER]. [Decision title]

**Date:** [DATE]
**Control(s):** [CCF-XX]

**Context:** [What problem or constraint came up?]

**Options considered:**
1. [Option A]: [pro / con]
2. [Option B]: [pro / con]

**Decision:** [What you chose]

**Why:** [The reason, in one or two sentences]

**Trade-off / revisit when:** [What you gave up, and what would change your mind]

---

## Starter entries to fill in

Write these up as you hit them. Each one maps to a likely interview question.

- **IAM users instead of IAM Identity Center:** the Free plan doesn't support AWS Organizations. What's the risk, and what would you do on a paid plan?
- **SecurityAudit instead of a custom policy:** a managed policy vs. writing your own least-privilege policy. What does SecurityAudit grant that you don't need?
- **Separating collect and evaluate:** why save evidence before judging it?
- **Fail closed:** why is an API error `error` and not `pass`?
- **Thresholds:** your key rotation age, vulnerability SLAs and why.
- **S3 encryption check:** S3 encrypts new objects by default. Keep the check, retire it, or require something stronger?
- **Zero secret scanning alerts:** what that proves and what it doesn't.
- **Requirement rollup:** how a requirement's status is decided when several controls map to it.
- **Public repo:** free security features vs. exposure. What did you do to keep it safe?
- **OIDC for CI:** why not store an access key as a GitHub secret?
