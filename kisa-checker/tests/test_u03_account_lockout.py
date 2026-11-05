"""KISA U-03 읽기 전용 판단 회귀 테스트."""
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from checks.u03_account_lockout import (
    _inline_deny, _parse_deny, _pam_faillock, check_u03_account_lockout,
)


class U03Tests(unittest.TestCase):
    def test_deny_boundary(self):
        self.assertEqual(_parse_deny("0"), 0)
        self.assertEqual(_parse_deny("10"), 10)
        self.assertEqual(_parse_deny("11"), 11)
        self.assertIsNone(_parse_deny("abc"))
        self.assertIsNone(_parse_deny("-1"))
        self.assertEqual(_inline_deny("auth required pam_faillock.so authfail deny=5"), 5)

    @patch("checks.u03_account_lockout.platform.system", return_value="Windows")
    def test_windows_not_applicable(self, _system):
        self.assertEqual(check_u03_account_lockout()["result"], "해당없음")

    @patch("checks.u03_account_lockout._active_lines")
    def test_pam_collects_active_authfail(self, lines):
        lines.return_value = [
            "auth required pam_faillock.so preauth",
            "auth [default=die] pam_faillock.so authfail deny=7",
            "auth sufficient pam_unix.so nullok",
        ]
        out = _pam_faillock("/etc/pam.d/system-auth")
        self.assertTrue(out["authfail"])
        self.assertEqual(out["inline_deny"], [7])

    def _mocked_check(self, config_deny, inline=None, both_active=True):
        with ExitStack() as stack:
            stack.enter_context(patch("checks.u03_account_lockout.platform.system", return_value="Linux"))
            stack.enter_context(patch("checks.u03_account_lockout._get_os_id", return_value="rocky"))
            stack.enter_context(patch(
                "checks.u03_account_lockout._get_config",
                return_value={"deny": config_deny, "raw_deny": str(config_deny), "readable": True}
            ))
            read_pam = stack.enter_context(patch("checks.u03_account_lockout._pam_faillock"))
            read_pam.side_effect = [
                {"authfail": True, "inline_deny": list(inline or []), "readable": True},
                {"authfail": both_active, "inline_deny": list(inline or []), "readable": True},
            ]
            return check_u03_account_lockout()

    def test_excessive_deny_is_vulnerable(self):
        result = self._mocked_check(11)
        self.assertEqual(result["result"], "취약")
        self.assertIn("deny=11", result["reason"])

    def test_zero_deny_is_vulnerable(self):
        self.assertEqual(self._mocked_check(0)["result"], "취약")

    def test_valid_deny_needs_manual_confirmation(self):
        self.assertEqual(self._mocked_check(5)["result"], "수동확인")
        self.assertEqual(self._mocked_check(10)["result"], "수동확인")

    def test_valid_inline_overrides_invalid_file(self):
        self.assertEqual(self._mocked_check(11, inline=[5])["result"], "수동확인")

    def test_unverified_pam_path_stays_manual(self):
        self.assertEqual(self._mocked_check(11, both_active=False)["result"], "수동확인")


if __name__ == "__main__":
    unittest.main()
