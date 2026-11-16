"""GitHub checks: CCF-06 to CCF-08.

Uses a fine-grained, read-only token (GITHUB_TOKEN in .env) scoped to one repo.
Secret values are never saved: only alert metadata.
"""
from datetime import datetime

import requests

from .common import (AT_RISK, ERROR, FAIL, PASS, Result, latest_evidence,
                     missing, now_utc, rel, save_evidence)

API = "https://api.github.com"
SLA_DAYS = {"critical": 15, "high": 30, "medium": 90}


def _get(token, path):
    r = requests.get(f"{API}{path}", timeout=30, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        body = r.json()
    except ValueError:
        body = {"message": r.text[:200]}
    return r.status_code, body


# ---------- collectors ----------

def collect_branch_protection(token, repo, who):
    status, body = _get(token, f"/repos/{repo}/branches/main/protection")
    r_status, rules = _get(token, f"/repos/{repo}/rules/branches/main")
    return save_evidence("gh_branch_protection", {
        "protection_status": status, "protection": body,
        "rules_status": r_status, "rules": rules,
    }, who)


def collect_dependabot(token, repo, who):
    status, body = _get(token, f"/repos/{repo}/dependabot/alerts?state=open&per_page=100")
    alerts = []
    if status == 200:
        for a in body:
            adv = a.get("security_advisory", {})
            alerts.append({
                "number": a.get("number"),
                "package": a.get("dependency", {}).get("package", {}).get("name"),
                "manifest": a.get("dependency", {}).get("manifest_path"),
                "severity": adv.get("severity"),
                "ghsa_id": adv.get("ghsa_id"),
                "cve_id": adv.get("cve_id"),
                "created_at": a.get("created_at"),
            })
    return save_evidence("gh_dependabot", {"status": status, "message": body if status != 200 else "",
                                           "alerts": alerts}, who)


def collect_secret_scanning(token, repo, who):
    status, body = _get(token, f"/repos/{repo}/secret-scanning/alerts?state=open&per_page=100")
    alerts = []
    if status == 200:
        for a in body:  # deliberately drop the "secret" field
            alerts.append({
                "number": a.get("number"),
                "secret_type": a.get("secret_type_display_name") or a.get("secret_type"),
                "created_at": a.get("created_at"),
                "validity": a.get("validity"),
            })
    return save_evidence("gh_secret_scanning", {"status": status, "message": body if status != 200 else "",
                                                "alerts": alerts}, who)


# ---------- evaluators ----------

def evaluate_main_branch_protected(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("gh_branch_protection")
    if env is None:
        return missing("gh_branch_protection")
    d = env["data"]
    ruleset_pr = d.get("rules_status") == 200 and any(
        r.get("type") == "pull_request" for r in (d.get("rules") or []))
    if d.get("protection_status") == 200:
        reviews = (d["protection"].get("required_pull_request_reviews") or {})
        count = reviews.get("required_approving_review_count", 0)
        admins = (d["protection"].get("enforce_admins") or {}).get("enabled", False)
        if count >= 1 or ruleset_pr:
            if not admins:
                return Result(AT_RISK, f"main requires {count} approval(s), but admins can bypass",
                              "protected", ["Turn on 'Do not allow bypassing the above settings'"], rel(path))
            return Result(PASS, f"main requires {count} approval(s), admins included", "protected", [], rel(path))
        return Result(FAIL, "main is protected but doesn't require an approved pull request",
                      "0 approvals required", [], rel(path))
    if d.get("protection_status") == 404:
        if ruleset_pr:
            return Result(PASS, "A ruleset requires a pull request on main", "ruleset", [], rel(path))
        return Result(FAIL, "main is not protected: anyone with write access can push directly",
                      "unprotected", [], rel(path))
    return Result(ERROR, f"Could not read branch protection (HTTP {d.get('protection_status')})",
                  "", [str(d.get("protection", {}).get("message", ""))], rel(path))


def evaluate_dependabot_within_sla(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("gh_dependabot")
    if env is None:
        return missing("gh_dependabot")
    d = env["data"]
    msg = d.get("message", {}).get("message", "") if isinstance(d.get("message"), dict) else ""
    if d["status"] == 403 and "disabled" in msg.lower():
        return Result(FAIL, "Dependabot alerts are turned off for this repository", "off", [msg], rel(path))
    if d["status"] != 200:
        return Result(ERROR, f"Could not read Dependabot alerts (HTTP {d['status']})", "", [], rel(path))
    today = today or now_utc()
    overdue, open_serious = [], []
    for a in d["alerts"]:
        sev = (a.get("severity") or "").lower()
        if sev not in SLA_DAYS:
            continue
        age = (today - datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))).days
        label = f"{a['package']} {a.get('cve_id') or a.get('ghsa_id')} ({sev}, {age} days open)"
        if age > SLA_DAYS[sev]:
            overdue.append(label)
        elif sev in ("critical", "high"):
            open_serious.append(label + f": due in {SLA_DAYS[sev] - age} days")
    metric = f"{len(d['alerts'])} open alert(s)"
    if overdue:
        return Result(FAIL, f"{len(overdue)} alert(s) past SLA", metric, overdue, rel(path))
    if open_serious:
        return Result(AT_RISK, f"{len(open_serious)} critical/high alert(s) open, within SLA", metric,
                      open_serious, rel(path))
    return Result(PASS, "No open alerts past SLA", metric, [], rel(path))


def evaluate_no_open_secret_alerts(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("gh_secret_scanning")
    if env is None:
        return missing("gh_secret_scanning")
    d = env["data"]
    if d["status"] == 404:
        return Result(FAIL, "Secret scanning is off, or the token can't see it", "off", [], rel(path))
    if d["status"] != 200:
        return Result(ERROR, f"Could not read secret scanning alerts (HTTP {d['status']})", "", [], rel(path))
    if d["alerts"]:
        items = [f"#{a['number']} {a['secret_type']} (opened {a['created_at'][:10]})" for a in d["alerts"]]
        return Result(FAIL, f"{len(items)} open secret alert(s): revoke, rotate, then close", f"{len(items)} open",
                      items, rel(path))
    return Result(PASS, "0 open alerts (covers GitHub's supported secret patterns in this repo only)",
                  "0 open", [], rel(path))
