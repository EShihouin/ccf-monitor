"""ccf-monitor: test every control in controls/catalog.csv against live evidence.

Usage (from the repo folder, with .venv active):
  python3 monitor.py                # collect fresh evidence, then evaluate everything
  python3 monitor.py --offline      # evaluate the newest saved evidence only (no API calls)
  python3 monitor.py --skip github  # skip a system: aws, github or ai

Outputs (gitignored): output/results.json, output/results.csv, output/dashboard.html
"""
import argparse
import csv
import json
import os
import subprocess
import sys

from checks import ai_checks, aws_checks, github_checks, scanner_checks
from checks.common import AT_RISK, ERROR, FAIL, PASS, ROOT, Result

# Which evaluator answers each catalog row, and which evidence source it needs.
EVALUATORS = {
    "mfa_for_humans": (aws_checks.evaluate_mfa_for_humans, "aws_credential_report"),
    "root_locked_down": (aws_checks.evaluate_root_locked_down, "aws_credential_report"),
    "access_keys_rotated": (aws_checks.evaluate_access_keys_rotated, "aws_credential_report"),
    "cloudtrail_logging": (aws_checks.evaluate_cloudtrail_logging, "aws_cloudtrail"),
    "s3_not_public": (aws_checks.evaluate_s3_not_public, "aws_s3"),
    "main_branch_protected": (github_checks.evaluate_main_branch_protected, "gh_branch_protection"),
    "dependabot_within_sla": (github_checks.evaluate_dependabot_within_sla, "gh_dependabot"),
    "no_open_secret_alerts": (github_checks.evaluate_no_open_secret_alerts, "gh_secret_scanning"),
    "ai_agent_tools_approved": (ai_checks.evaluate_ai_agent_tools_approved, "ai_agent_config"),
    "trivy_no_critical_high": (scanner_checks.evaluate_trivy_no_critical_high, None),
    "gitleaks_no_leaks": (scanner_checks.evaluate_gitleaks_no_leaks, None),
}
FRAMEWORKS = {"nist_800_53": "NIST 800-53", "iso_27001": "ISO 27001", "soc2": "SOC 2"}
RANK = {PASS: 0, AT_RISK: 1, FAIL: 2, ERROR: 3}


def load_env():
    """Read KEY=VALUE lines from .env (gitignored) without printing them."""
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def detect_repo():
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        name = url.rstrip("/").removesuffix(".git").split("github.com")[-1].lstrip(":/")
        return name or None
    except Exception:
        return None


def collect(args):
    """Pull fresh evidence. A source that fails is recorded so its controls fail closed."""
    failed = {}

    if "aws" not in args.skip:
        try:
            import boto3
            session = boto3.Session(profile_name=args.profile)
            who, account = aws_checks.collect_identity(session)
            print(f"AWS as {who}")
            for source, fn in [("aws_credential_report", lambda: aws_checks.collect_credential_report(session, who)),
                               ("aws_cloudtrail", lambda: aws_checks.collect_cloudtrail(session, who)),
                               ("aws_s3", lambda: aws_checks.collect_s3(session, account, who))]:
                try:
                    fn()
                    print(f"  collected {source}")
                except Exception as exc:
                    failed[source] = f"{type(exc).__name__}: {str(exc)[:150]}"
                    print(f"  FAILED {source}: {failed[source]}")
        except Exception as exc:
            for s in ("aws_credential_report", "aws_cloudtrail", "aws_s3"):
                failed[s] = f"AWS sign-in failed: {str(exc)[:150]}"
            print(f"AWS sign-in failed: {exc}")

    if "github" not in args.skip:
        token = os.environ.get("GITHUB_TOKEN")
        sources = ("gh_branch_protection", "gh_dependabot", "gh_secret_scanning")
        if not token or not args.repo:
            for s in sources:
                failed[s] = "No GITHUB_TOKEN in .env or no repo name"
            print("GitHub skipped: no GITHUB_TOKEN in .env or no repo name")
        else:
            who = f"github-token ({args.repo}, read-only)"
            print(f"GitHub repo {args.repo}")
            for source, fn in [("gh_branch_protection", github_checks.collect_branch_protection),
                               ("gh_dependabot", github_checks.collect_dependabot),
                               ("gh_secret_scanning", github_checks.collect_secret_scanning)]:
                try:
                    fn(token, args.repo, who)
                    print(f"  collected {source}")
                except Exception as exc:
                    failed[source] = f"{type(exc).__name__}: {str(exc)[:150]}"
                    print(f"  FAILED {source}: {failed[source]}")

    if "ai" not in args.skip:
        try:
            ai_checks.collect_ai_config("local file read")
            print("  collected ai_agent_config")
        except Exception as exc:
            failed["ai_agent_config"] = f"{type(exc).__name__}: {str(exc)[:150]}"

    return failed


def split(cell):
    return [x.strip() for x in (cell or "").split(";") if x.strip()]


def run(args):
    with open(os.path.join(ROOT, "controls", "catalog.csv"), newline="") as f:
        catalog = list(csv.DictReader(f))

    failed = {} if args.offline else collect(args)

    controls = []
    for row in catalog:
        fn, source = EVALUATORS[row["check"]]
        if source in failed:
            r = Result(ERROR, f"Evidence collection failed: {failed[source]}", "collection failed")
        else:
            try:
                r = fn()
            except Exception as exc:  # a broken check is an error, never a pass
                r = Result(ERROR, f"Check crashed: {type(exc).__name__}: {exc}", "check error")
        controls.append({
            "id": row["ccf_id"], "name": row["name"], "owner": row["owner"], "frequency": row["frequency"],
            "statement": row["statement"], "risk": row["risk"], "pass_rule": row["pass_rule"],
            "mappings": {k: split(row[k]) for k in FRAMEWORKS}, "cis_aws": row.get("cis_aws", ""),
            "evidence_source": row["evidence_source"], **r.to_dict(),
        })

    frameworks = []
    for key, label in FRAMEWORKS.items():
        reqs = {}
        for c in controls:
            for req in c["mappings"][key]:
                reqs.setdefault(req, []).append(c)
        rows = [{"id": req, "status": max((x["status"] for x in cs), key=RANK.get),
                 "controls": [x["id"] for x in cs]} for req, cs in sorted(reqs.items())]
        ready = sum(1 for r in rows if r["status"] in (PASS, AT_RISK))
        frameworks.append({"key": key, "label": label, "total": len(rows), "ready": ready,
                           "pct": round(100 * ready / len(rows)) if rows else 0,
                           "gaps": [r for r in rows if r["status"] in (FAIL, ERROR)]})

    counts = {s: sum(1 for c in controls if c["status"] == s) for s in RANK}
    from checks.common import now_utc
    return {"as_of": now_utc().strftime("%Y-%m-%d %H:%M UTC"), "repo": args.repo or "",
            "counts": counts, "controls": controls, "frameworks": frameworks}


def write_outputs(results):
    out = os.path.join(ROOT, "output")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(out, "results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ccf_id", "control", "owner", "status", "metric", "summary",
                    "nist_800_53", "iso_27001", "soc2", "evidence", "as_of"])
        for c in results["controls"]:
            w.writerow([c["id"], c["name"], c["owner"], c["status"], c["metric"], c["summary"],
                        "; ".join(c["mappings"]["nist_800_53"]), "; ".join(c["mappings"]["iso_27001"]),
                        "; ".join(c["mappings"]["soc2"]), c["evidence"], results["as_of"]])
    with open(os.path.join(ROOT, "dashboard_template.html")) as f:
        html = f.read().replace("__CCF_DATA__", json.dumps(results).replace("</", "<\\/"))
    with open(os.path.join(out, "dashboard.html"), "w") as f:
        f.write(html)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", default="ccf", help="AWS CLI profile (default: ccf)")
    p.add_argument("--repo", default=None, help="owner/repo (default: this repo's origin)")
    p.add_argument("--offline", action="store_true", help="evaluate saved evidence only")
    p.add_argument("--skip", nargs="*", default=[], choices=["aws", "github", "ai"])
    args = p.parse_args()
    load_env()
    args.repo = args.repo or os.environ.get("CCF_REPO") or detect_repo()

    results = run(args)
    write_outputs(results)

    c = results["counts"]
    print(f"\nControl health as of {results['as_of']}: "
          f"{c[PASS]} pass, {c[AT_RISK]} at risk, {c[FAIL]} fail, {c[ERROR]} error")
    for fw in results["frameworks"]:
        print(f"  {fw['label']:<12} {fw['pct']:>3}% ready ({fw['ready']}/{fw['total']} requirements)")
    print()
    for ctl in results["controls"]:
        print(f"  [{ctl['status'].upper():<7}] {ctl['id']} {ctl['name']}: {ctl['summary']}")
        for item in ctl["items"][:5]:
            print(f"             - {item}")
    print("\nDashboard: open output/dashboard.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
