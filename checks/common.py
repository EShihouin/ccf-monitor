"""Shared pieces for every check.

Every check has two halves:
  collect_*  -> calls a system's API and saves the raw response to evidence/
  evaluate_* -> reads only that saved evidence and returns a Result

Keeping them separate means the evidence is reproducible and auditable,
and the pass/fail logic can be tested offline (see tests/).
"""
import glob
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVIDENCE_DIR = os.path.join(ROOT, "evidence")

PASS, AT_RISK, FAIL, ERROR = "pass", "at_risk", "fail", "error"


@dataclass
class Result:
    status: str          # pass, at_risk, fail or error
    summary: str         # one line an owner can act on
    metric: str = ""     # the number behind the status, e.g. "2/3 users"
    items: list = field(default_factory=list)  # the specific records behind a fail
    evidence: str = ""   # which evidence file was judged

    def to_dict(self):
        return asdict(self)


def now_utc():
    return datetime.now(timezone.utc)


def save_evidence(source, data, collected_by):
    """Save raw API output with a timestamp and the identity that pulled it."""
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    ts = now_utc().strftime("%Y-%m-%dT%H%M%SZ")
    path = os.path.join(EVIDENCE_DIR, f"{source}_{ts}.json")
    envelope = {
        "source": source,
        "collected_at": now_utc().isoformat(),
        "collected_by": collected_by,
        "data": data,
    }
    with open(path, "w") as f:
        json.dump(envelope, f, indent=2, default=str)
    return path


def latest_evidence(source):
    """Return (path, envelope) for the newest evidence file of a source, or (None, None)."""
    files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, f"{source}_*.json")))
    if not files:
        return None, None
    path = files[-1]
    with open(path) as f:
        return path, json.load(f)


def latest_raw(pattern):
    """Return (path, parsed JSON) for the newest file matching a glob in evidence/ (scanner output)."""
    files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, pattern)))
    if not files:
        return None, None
    path = files[-1]
    with open(path) as f:
        text = f.read().strip()
    return path, (json.loads(text) if text else [])


def rel(path):
    return os.path.relpath(path, ROOT) if path else ""


def missing(source):
    """Fail closed: no evidence is an error, never a pass."""
    return Result(ERROR, f"No evidence for {source}. Run the collector first.", "no evidence")
