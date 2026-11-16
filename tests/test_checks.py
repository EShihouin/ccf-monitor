"""Test the tests: every check must catch a planted failure and pass a clean case.

Run from the repo folder:  python3 -m unittest -v
No AWS or GitHub access needed: each test feeds the evaluator made-up evidence.
"""
import unittest
from datetime import datetime, timedelta, timezone

from checks import ai_checks, aws_checks, github_checks, scanner_checks

TODAY = datetime(2026, 11, 16, tzinfo=timezone.utc)


def days_ago(n):
    return (TODAY - timedelta(days=n)).isoformat()


def user(name, password="true", mfa="true", key1="false", rotated="N/A", used="N/A", pw_used="N/A"):
    return {"user": name, "password_enabled": password, "mfa_active": mfa, "password_last_used": pw_used,
            "access_key_1_active": key1, "access_key_1_last_rotated": rotated, "access_key_1_last_used_date": used,
            "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"}


ROOT_OK = user("<root_account>", password="not_supported", pw_used=days_ago(60))


def env(data):
    return {"data": data}


class AwsChecks(unittest.TestCase):
    def test_mfa_catches_user_without_mfa(self):
        r = aws_checks.evaluate_mfa_for_humans(env([ROOT_OK, user("admin"), user("demo-contractor", mfa="false")]))
        self.assertEqual(r.status, "fail")
        self.assertIn("demo-contractor", r.items)

    def test_mfa_ignores_users_without_console_password(self):
        r = aws_checks.evaluate_mfa_for_humans(env([ROOT_OK, user("admin"), user("ccf-auditor", password="false", mfa="false")]))
        self.assertEqual(r.status, "pass")

    def test_root_with_active_key_fails(self):
        bad_root = dict(ROOT_OK, access_key_1_active="true")
        self.assertEqual(aws_checks.evaluate_root_locked_down(env([bad_root]), TODAY).status, "fail")

    def test_root_recently_used_is_at_risk(self):
        recent = dict(ROOT_OK, password_last_used=days_ago(3))
        self.assertEqual(aws_checks.evaluate_root_locked_down(env([recent]), TODAY).status, "at_risk")

    def test_old_access_key_fails(self):
        old = user("ccf-auditor", password="false", key1="true", rotated=days_ago(120), used=days_ago(1))
        self.assertEqual(aws_checks.evaluate_access_keys_rotated(env([ROOT_OK, old]), TODAY).status, "fail")

    def test_new_used_key_passes(self):
        new = user("ccf-auditor", password="false", key1="true", rotated=days_ago(10), used=days_ago(1))
        self.assertEqual(aws_checks.evaluate_access_keys_rotated(env([ROOT_OK, new]), TODAY).status, "pass")

    def test_no_trail_fails(self):
        self.assertEqual(aws_checks.evaluate_cloudtrail_logging(env({"trails": []})).status, "fail")

    def test_multi_region_logging_trail_passes(self):
        t = {"Name": "org", "IsLogging": True, "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}
        self.assertEqual(aws_checks.evaluate_cloudtrail_logging(env({"trails": [t]})).status, "pass")

    def test_unreadable_trail_status_is_error_not_pass(self):
        t = {"Name": "org", "IsLogging": None, "IsMultiRegionTrail": True}
        self.assertEqual(aws_checks.evaluate_cloudtrail_logging(env({"trails": [t]})).status, "error")

    def test_bucket_without_block_fails(self):
        d = {"account_block": None, "account_block_error": "NoSuchPublicAccessBlockConfiguration",
             "buckets": [{"name": "b1", "block": None, "block_error": "NoSuchPublicAccessBlockConfiguration",
                          "encryption": ["AES256"]}]}
        self.assertEqual(aws_checks.evaluate_s3_not_public(env(d)).status, "fail")

    def test_no_account_block_is_at_risk(self):
        full = {k: True for k in aws_checks.BPA_KEYS}
        d = {"account_block": None, "account_block_error": "NoSuchPublicAccessBlockConfiguration",
             "buckets": [{"name": "b1", "block": full, "encryption": ["AES256"]}]}
        self.assertEqual(aws_checks.evaluate_s3_not_public(env(d)).status, "at_risk")

    def test_access_denied_is_error(self):
        d = {"account_block": None, "account_block_error": "AccessDenied", "buckets": []}
        self.assertEqual(aws_checks.evaluate_s3_not_public(env(d)).status, "error")


class GithubChecks(unittest.TestCase):
    def test_unprotected_main_fails(self):
        d = {"protection_status": 404, "protection": {}, "rules_status": 200, "rules": []}
        self.assertEqual(github_checks.evaluate_main_branch_protected(env(d)).status, "fail")

    def test_protected_main_passes(self):
        d = {"protection_status": 200, "rules_status": 200, "rules": [],
             "protection": {"required_pull_request_reviews": {"required_approving_review_count": 1},
                            "enforce_admins": {"enabled": True}}}
        self.assertEqual(github_checks.evaluate_main_branch_protected(env(d)).status, "pass")

    def test_overdue_critical_fails(self):
        d = {"status": 200, "alerts": [{"package": "django", "severity": "critical", "cve_id": "CVE-X",
                                        "created_at": days_ago(20)}]}
        self.assertEqual(github_checks.evaluate_dependabot_within_sla(env(d), TODAY).status, "fail")

    def test_new_high_is_at_risk(self):
        d = {"status": 200, "alerts": [{"package": "requests", "severity": "high", "cve_id": "CVE-Y",
                                        "created_at": days_ago(1)}]}
        self.assertEqual(github_checks.evaluate_dependabot_within_sla(env(d), TODAY).status, "at_risk")

    def test_open_secret_alert_fails(self):
        d = {"status": 200, "alerts": [{"number": 1, "secret_type": "AWS key", "created_at": days_ago(1)}]}
        self.assertEqual(github_checks.evaluate_no_open_secret_alerts(env(d)).status, "fail")


class AiAndScannerChecks(unittest.TestCase):
    def test_write_tool_without_approval_fails(self):
        d = {"agent": {"name": "a", "owner": "team", "tools": [{"name": "crm.update", "access": "write"}]},
             "approved": {"approved_tools": ["crm.update"]}}
        self.assertEqual(ai_checks.evaluate_ai_agent_tools_approved(env(d)).status, "fail")

    def test_clean_agent_passes(self):
        d = {"agent": {"name": "a", "owner": "team", "tools": [
                {"name": "crm.read", "access": "read"},
                {"name": "crm.update", "access": "write", "requires_human_approval": True}]},
             "approved": {"approved_tools": ["crm.read", "crm.update"]}}
        self.assertEqual(ai_checks.evaluate_ai_agent_tools_approved(env(d)).status, "pass")

    def test_trivy_critical_fails(self):
        data = {"Results": [{"Vulnerabilities": [{"PkgName": "django", "InstalledVersion": "2.2.0",
                                                  "VulnerabilityID": "CVE-Z", "Severity": "CRITICAL"}]}]}
        self.assertEqual(scanner_checks.evaluate_trivy_no_critical_high(data).status, "fail")

    def test_gitleaks_finding_fails_without_showing_secret(self):
        data = [{"RuleID": "aws-access-token", "File": "config.py", "StartLine": 1, "Secret": "AKIAFAKE"}]
        r = scanner_checks.evaluate_gitleaks_no_leaks(data)
        self.assertEqual(r.status, "fail")
        self.assertNotIn("AKIAFAKE", " ".join(r.items))


if __name__ == "__main__":
    unittest.main()
