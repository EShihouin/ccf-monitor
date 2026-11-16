"""AWS checks: CCF-01 to CCF-05.

Collectors use the read-only `ccf` profile (SecurityAudit + ViewOnlyAccess).
Evaluators read only the saved evidence.
"""
import csv
import io
import time
from datetime import datetime, timezone

from .common import (AT_RISK, ERROR, FAIL, PASS, Result, latest_evidence,
                     missing, now_utc, rel, save_evidence)

BPA_KEYS = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]


# ---------- helpers ----------

def _parse_date(value):
    """Credential report dates are ISO strings, or 'N/A' / 'no_information' / 'not_supported'."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _days_since(value, today=None):
    d = _parse_date(value)
    if d is None:
        return None
    today = today or now_utc()
    return (today - d).days


def _error_code(exc):
    return getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)


# ---------- collectors ----------

def collect_identity(session):
    ident = session.client("sts").get_caller_identity()
    return ident["Arn"], ident["Account"]


def collect_credential_report(session, who):
    """CCF-01, 02, 03. One report covers every IAM user, so the full population is tested."""
    iam = session.client("iam")
    for _ in range(20):  # the report is generated asynchronously
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(2)
    content = iam.get_credential_report()["Content"].decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(content)))
    return save_evidence("aws_credential_report", rows, who)


def collect_cloudtrail(session, who):
    """CCF-04."""
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    for t in trails:
        try:
            status = ct.get_trail_status(Name=t["TrailARN"])
            t["IsLogging"] = status.get("IsLogging", False)
        except Exception as exc:  # fail closed: unknown logging state
            t["IsLogging"] = None
            t["StatusError"] = _error_code(exc)
    return save_evidence("aws_cloudtrail", {"trails": trails}, who)


def collect_s3(session, account_id, who):
    """CCF-05. Account-level and bucket-level Block Public Access, plus default encryption."""
    data = {"account_block": None, "account_block_error": None, "buckets": []}
    try:
        cfg = session.client("s3control").get_public_access_block(AccountId=account_id)
        data["account_block"] = cfg["PublicAccessBlockConfiguration"]
    except Exception as exc:
        code = _error_code(exc)
        data["account_block_error"] = code  # NoSuchPublicAccessBlockConfiguration = not set
    s3 = session.client("s3")
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        entry = {"name": name, "block": None, "block_error": None, "encryption": None, "encryption_error": None}
        try:
            entry["block"] = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except Exception as exc:
            entry["block_error"] = _error_code(exc)
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            entry["encryption"] = [r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules]
        except Exception as exc:
            entry["encryption_error"] = _error_code(exc)
        data["buckets"].append(entry)
    return save_evidence("aws_s3", data, who)


# ---------- evaluators ----------

def evaluate_mfa_for_humans(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("aws_credential_report")
    if env is None:
        return missing("aws_credential_report")
    rows = [r for r in env["data"] if r["user"] != "<root_account>"]
    humans = [r for r in rows if r.get("password_enabled") == "true"]
    no_mfa = [r["user"] for r in humans if r.get("mfa_active") != "true"]
    metric = f"{len(humans) - len(no_mfa)}/{len(humans)} console users have MFA"
    if no_mfa:
        return Result(FAIL, f"{len(no_mfa)} console user(s) without MFA", metric, no_mfa, rel(path))
    return Result(PASS, "Every IAM user with a console password has MFA", metric, [], rel(path))


def evaluate_root_locked_down(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("aws_credential_report")
    if env is None:
        return missing("aws_credential_report")
    root = next((r for r in env["data"] if r["user"] == "<root_account>"), None)
    if root is None:
        return Result(ERROR, "Root row missing from the credential report", "", [], rel(path))
    problems = []
    if root.get("mfa_active") != "true":
        problems.append("root has no MFA")
    for n in ("1", "2"):
        if root.get(f"access_key_{n}_active") == "true":
            problems.append(f"root access key {n} is active")
    if problems:
        return Result(FAIL, "Root is not locked down", f"{len(problems)} problem(s)", problems, rel(path))
    used = _days_since(root.get("password_last_used"), today)
    if used is not None and used <= 30:
        return Result(AT_RISK, f"Root has MFA and no keys, but was used {used} day(s) ago",
                      "MFA on, 0 keys", ["Use root only for break-glass tasks"], rel(path))
    return Result(PASS, "Root has MFA, no access keys, and no recent use", "MFA on, 0 keys", [], rel(path))


def evaluate_access_keys_rotated(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("aws_credential_report")
    if env is None:
        return missing("aws_credential_report")
    fails, risks, active = [], [], 0
    for r in env["data"]:
        if r["user"] == "<root_account>":
            continue  # root keys are CCF-02
        for n in ("1", "2"):
            if r.get(f"access_key_{n}_active") != "true":
                continue
            active += 1
            age = _days_since(r.get(f"access_key_{n}_last_rotated"), today)
            used = r.get(f"access_key_{n}_last_used_date")
            label = f"{r['user']} key {n} ({age} days old)"
            if age is None:
                risks.append(f"{r['user']} key {n}: rotation date unknown")
            elif age > 90:
                fails.append(label)
            elif age > 75:
                risks.append(label + ": rotate within 15 days")
            elif _parse_date(used) is None and age > 7:
                risks.append(f"{r['user']} key {n}: active but never used")
    metric = f"{active} active key(s)"
    if fails:
        return Result(FAIL, f"{len(fails)} key(s) older than 90 days", metric, fails, rel(path))
    if risks:
        return Result(AT_RISK, "Keys need attention soon", metric, risks, rel(path))
    return Result(PASS, "All active keys are under 75 days old and in use", metric, [], rel(path))


def evaluate_cloudtrail_logging(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("aws_cloudtrail")
    if env is None:
        return missing("aws_cloudtrail")
    trails = env["data"]["trails"]
    if not trails:
        return Result(FAIL, "No CloudTrail trail exists", "0 trails",
                      ["Only the default 90-day event history is available"], rel(path))
    if any(t.get("IsLogging") is None for t in trails):
        return Result(ERROR, "Could not read logging status for a trail", f"{len(trails)} trail(s)",
                      [t.get("Name", "?") for t in trails if t.get("IsLogging") is None], rel(path))
    good = [t for t in trails if t.get("IsLogging") and t.get("IsMultiRegionTrail")]
    if not good:
        return Result(FAIL, "No multi-region trail is logging", f"{len(trails)} trail(s)",
                      [t.get("Name", "?") for t in trails], rel(path))
    no_validation = [t["Name"] for t in good if not t.get("LogFileValidationEnabled")]
    if no_validation:
        return Result(AT_RISK, "Logging in all regions, but log file validation is off",
                      f"{len(good)} multi-region trail(s)", no_validation, rel(path))
    return Result(PASS, "A multi-region trail is logging with validation", f"{len(good)} trail(s)", [], rel(path))


def _fully_blocked(cfg):
    return bool(cfg) and all(cfg.get(k) for k in BPA_KEYS)


def evaluate_s3_not_public(env=None, today=None):
    path, env = (None, env) if env is not None else latest_evidence("aws_s3")
    if env is None:
        return missing("aws_s3")
    d = env["data"]
    acct_err = d.get("account_block_error")
    if acct_err and acct_err != "NoSuchPublicAccessBlockConfiguration":
        return Result(ERROR, f"Could not read account-level Block Public Access ({acct_err})", "", [], rel(path))
    account_blocked = _fully_blocked(d.get("account_block"))
    buckets = d.get("buckets", [])
    exposed, unencrypted, unknown = [], [], []
    for b in buckets:
        if b.get("block_error") not in (None, "NoSuchPublicAccessBlockConfiguration"):
            unknown.append(f"{b['name']}: {b['block_error']}")
        elif not account_blocked and not _fully_blocked(b.get("block")):
            exposed.append(b["name"])
        if not b.get("encryption"):
            unencrypted.append(b["name"])
    metric = f"{len(buckets)} bucket(s); account-level block {'on' if account_blocked else 'off'}"
    if unknown:
        return Result(ERROR, "Could not read some bucket settings", metric, unknown, rel(path))
    if exposed or unencrypted:
        items = [f"{n}: public access not fully blocked" for n in exposed] + \
                [f"{n}: no default encryption" for n in unencrypted]
        return Result(FAIL, "Some buckets could be public or unencrypted", metric, items, rel(path))
    if not account_blocked:
        lead = "No buckets yet" if not buckets else "Every bucket is blocked"
        return Result(AT_RISK, f"{lead}, but account-level Block Public Access is off",
                      metric, ["Future buckets aren't covered until it's turned on for the account"], rel(path))
    return Result(PASS, "Public access blocked for the account and every bucket is encrypted", metric, [], rel(path))
