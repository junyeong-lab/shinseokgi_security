"""U-06 su 그룹 접근통제 단위 테스트 (Python 3.9/3.12)."""
import stat
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

from checks import u06_su_restriction as u06


class U06Tests(unittest.TestCase):
    def test_group_parser_ignores_members_and_invalid_gid(self):
        with patch.object(u06, "_active_lines", return_value=[
            "root:x:0:root",
            "wheel:x:10:admin,user",
            "invalid:x:not-an-int:user",
        ]):
            self.assertEqual(u06._group_names(), {0: "root", 10: "wheel"})

    def test_pam_required_wheel_use_uid_detected(self):
        result = u06._pam_wheel_summary(
            ["auth required pam_wheel.so use_uid"], {10: "wheel"}
        )
        self.assertTrue(result["restrictive_rule_found"])
        self.assertTrue(result["groups_verified"])
        self.assertEqual(result["wheel_module_count"], 1)

    def test_pam_group_option_detected(self):
        result = u06._pam_wheel_summary(
            ["auth requisite /usr/lib64/security/pam_wheel.so group=admins"],
            {900: "admins"},
        )
        self.assertTrue(result["restrictive_rule_found"])

    def test_pam_sufficient_is_not_a_gate(self):
        result = u06._pam_wheel_summary(
            ["auth sufficient pam_wheel.so use_uid"], {10: "wheel"}
        )
        self.assertFalse(result["restrictive_rule_found"])
        self.assertTrue(result["complex_auth_flow"])

    def test_pam_deny_and_trust_not_accepted(self):
        for option in ("deny", "trust", "root_only"):
            with self.subTest(option=option):
                result = u06._pam_wheel_summary(
                    ["auth required pam_wheel.so use_uid " + option], {10: "wheel"}
                )
                self.assertFalse(result["restrictive_rule_found"])

    def test_pam_missing_group_requires_review(self):
        result = u06._pam_wheel_summary(
            ["auth required pam_wheel.so use_uid"], {0: "root"}
        )
        self.assertFalse(result["restrictive_rule_found"])

    def test_pam_include_marked_complex(self):
        result = u06._pam_wheel_summary(
            ["auth include system-auth", "auth required pam_wheel.so use_uid"],
            {10: "wheel"},
        )
        self.assertTrue(result["complex_auth_flow"])

    def _metadata(self, mode, acl=None, uid=0, gid=10):
        fake = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)
        with ExitStack() as stack:
            stack.enter_context(patch.object(u06.Path, "lstat", return_value=fake))
            stack.enter_context(patch.object(
                u06.os, "listxattr", return_value=list(acl or [])
            ))
            return u06._su_metadata(u06.SU_PATH, {10: "wheel"})

    def test_su_group_mode_4750_passes(self):
        result = self._metadata(0o4750)
        self.assertTrue(result["group_restriction"])
        self.assertFalse(result["world_executable"])
        self.assertEqual(result["mode_octal"], "4750")

    def test_su_symlink_not_accepted(self):
        fake = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=10)
        with patch.object(u06.Path, "lstat", return_value=fake):
            result = u06._su_metadata(u06.SU_PATH, {10: "wheel"})
        self.assertFalse(result["group_restriction"])

    def test_su_world_executable_not_accepted(self):
        self.assertFalse(self._metadata(0o4755)["group_restriction"])

    def test_su_acl_not_accepted_without_review(self):
        result = self._metadata(0o4750, ["system.posix_acl_access"])
        self.assertFalse(result["group_restriction"])
        self.assertEqual(result["acl_status"], "있음")

    def test_su_without_root_owner_not_accepted(self):
        self.assertFalse(self._metadata(0o4750, uid=1000)["group_restriction"])

    def _check(self, group_gate, pam_gate=False, world_executable=True):
        with ExitStack() as stack:
            stack.enter_context(patch.object(u06.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(u06, "_active_lines", side_effect=lambda path: (
                ["ID=rocky"] if str(path) == "/etc/os-release" else
                ["auth required pam_wheel.so use_uid"] if str(path) == "/etc/pam.d/su" else []
            )))
            stack.enter_context(patch.object(u06, "_group_names", return_value={10: "wheel"}))
            stack.enter_context(patch.object(u06, "_su_metadata", return_value={
                "group_restriction": group_gate,
                "world_executable": world_executable,
            }))
            stack.enter_context(patch.object(u06, "_pam_wheel_summary", return_value={
                "restrictive_rule_found": pam_gate,
            }))
            return u06.check_u06_su_restriction()

    def test_group_gate_passes(self):
        self.assertEqual(self._check(True)["result"], "양호")

    def test_pam_only_requires_manual_verification(self):
        self.assertEqual(self._check(False, pam_gate=True)["result"], "수동확인")

    def test_world_executable_without_verified_pam_is_manual(self):
        result = self._check(False, pam_gate=False)
        self.assertEqual(result["result"], "수동확인")
        self.assertIn("취약 가능성", result["reason"])

    @patch.object(u06.platform, "system", return_value="Windows")
    def test_windows_not_applicable(self, _system):
        self.assertEqual(u06.check_u06_su_restriction()["result"], "해당없음")


if __name__ == "__main__":
    unittest.main()
