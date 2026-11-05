"""U-02 초기 판정의 회귀 테스트. 표준 라이브러리만 사용."""
import unittest
from unittest.mock import patch

from checks.u02_password_policy import _age_issues, _key_values, check_u02_password_policy


class U02Tests(unittest.TestCase):
    def test_parse_active_values(self):
        values = _key_values([
            "PASS_MIN_DAYS 0", "PASS_MAX_DAYS   99999",
            "minlen = 8", "enforce_for_root"
        ])
        self.assertEqual(values["pass_min_days"], "0")
        self.assertEqual(values["pass_max_days"], "99999")
        self.assertEqual(values["minlen"], "8")
        self.assertEqual(values["enforce_for_root"], "enabled")

    def test_aging_boundaries(self):
        self.assertEqual(_age_issues("테스트", 1, 90), [])
        self.assertEqual(len(_age_issues("테스트", 0, 99999)), 2)

    @patch("checks.u02_password_policy.platform.system", return_value="Windows")
    def test_windows_not_applicable(self, _system):
        self.assertEqual(check_u02_password_policy()["result"], "해당없음")

    @patch("checks.u02_password_policy._pam_modules", return_value={"readable": True})
    @patch("checks.u02_password_policy._read_policy", return_value={"readable": True})
    @patch("checks.u02_password_policy._root_aging")
    @patch("checks.u02_password_policy._active_lines")
    @patch("checks.u02_password_policy.platform.system", return_value="Linux")
    def test_rocky_explicitly_weak_age_is_vulnerable(
        self, _system, active, aging, _policy, _pam
    ):
        def lines(path):
            if str(path) == "/etc/os-release":
                return ["NAME=\"Rocky Linux\"", "ID=rocky", "VERSION_ID=\"9.8\""]
            if str(path) == "/etc/login.defs":
                return ["PASS_MIN_DAYS 0", "PASS_MAX_DAYS 99999"]
            return []
        active.side_effect = lines
        aging.return_value = {"min_days": 0, "max_days": 99999, "status": "수집"}
        result = check_u02_password_policy()
        self.assertEqual(result["result"], "취약")
        self.assertIn("99999", result["reason"])

    @patch("checks.u02_password_policy._pam_modules", return_value={"readable": True})
    @patch("checks.u02_password_policy._read_policy", return_value={"readable": True})
    @patch("checks.u02_password_policy._root_aging")
    @patch("checks.u02_password_policy._active_lines")
    @patch("checks.u02_password_policy.platform.system", return_value="Linux")
    def test_rocky_age_ok_still_requires_manual_confirmation(
        self, _system, active, aging, _policy, _pam
    ):
        def lines(path):
            if str(path) == "/etc/os-release":
                return ["ID=rocky"]
            if str(path) == "/etc/login.defs":
                return ["PASS_MIN_DAYS 1", "PASS_MAX_DAYS 90"]
            return []
        active.side_effect = lines
        aging.return_value = {"min_days": 1, "max_days": 90, "status": "수집"}
        result = check_u02_password_policy()
        self.assertEqual(result["result"], "수동확인")


if __name__ == "__main__":
    unittest.main()
