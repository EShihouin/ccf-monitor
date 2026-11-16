"""Scanner checks: CCF-10 (Trivy) and CCF-11 (gitleaks).

These read the JSON the scanners already saved in evidence/ (trivy_*.json, gitleaks_*.json).
Secret values from gitleaks are never printed or copied: only rule, file and line.
"""
from .common import FAIL, PASS, ERROR, Result, latest_raw, rel


def evaluate_trivy_no_critical_high(env=None, today=None):
    path, data = (None, env) if env is not None else latest_raw("trivy_*.json")
    if data is None:
        return Result(ERROR, "No Trivy evidence. Run: trivy fs --scanners vuln --format json "
                             "--output evidence/trivy_$D.json demo-app/", "no evidence")
    counts, items = {"CRITICAL": 0, "HIGH": 0}, []
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            sev = v.get("Severity")
            if sev in counts:
                counts[sev] += 1
                items.append(f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('VulnerabilityID')} "
                             f"({sev.lower()}, fixed in {v.get('FixedVersion') or 'no fix yet'})")
    metric = f"{counts['CRITICAL']} critical, {counts['HIGH']} high"
    if counts["CRITICAL"] or counts["HIGH"]:
        return Result(FAIL, "Shipped dependencies have critical or high CVEs", metric, items[:25], rel(path))
    return Result(PASS, "No critical or high CVEs in scanned dependencies", metric, [], rel(path))


def evaluate_gitleaks_no_leaks(env=None, today=None):
    path, data = (None, env) if env is not None else latest_raw("gitleaks_*.json")
    if data is None:
        return Result(ERROR, "No gitleaks evidence. Run gitleaks with --report-path evidence/gitleaks_$D.json",
                      "no evidence")
    items = [f"{f.get('RuleID')} in {f.get('File')} line {f.get('StartLine')}" for f in data]
    if items:
        return Result(FAIL, f"{len(items)} secret(s) found: revoke and rotate, then remove", f"{len(items)} leak(s)",
                      items, rel(path))
    return Result(PASS, "No secrets found", "0 leaks", [], rel(path))
