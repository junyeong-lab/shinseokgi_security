"""KISA U-16/U-18 소유자·권한 메타데이터 회귀 테스트."""
import stat
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from checks import u16_passwd_permissions as u16
from checks import u18_shadow_permissions as u18


class FilePermissionTests(unittest.TestCase):
    def _check(self, mode, uid=0, file_type=stat.S_IFREG, allowed=0o644):
        fake = SimpleNamespace(st_mode=file_type | mode, st_uid=uid)
        with patch.object(Path, "lstat", return_value=fake):
            return u16._permission_result(
                Path("/etc/passwd"), allowed, "U-16", "test"
            )

    def test_passwd_0644_allowed(self):
        self.assertEqual(self._check(0o644)["result"], "양호")

    def test_passwd_0600_allowed(self):
        self.assertEqual(self._check(0o600)["result"], "양호")

    def test_passwd_0664_rejected_group_write(self):
        self.assertEqual(self._check(0o664)["result"], "취약")

    def test_passwd_0555_rejected_execute_bits(self):
        self.assertEqual(self._check(0o555)["result"], "취약")

    def test_passwd_4755_rejected_setuid(self):
        self.assertEqual(self._check(0o4755)["result"], "취약")

    def test_shadow_0400_allowed(self):
        self.assertEqual(self._check(0o400, allowed=0o400)["result"], "양호")

    def test_shadow_0000_allowed(self):
        self.assertEqual(self._check(0o000, allowed=0o400)["result"], "양호")

    def test_shadow_0600_rejected_owner_write(self):
        self.assertEqual(self._check(0o600, allowed=0o400)["result"], "취약")

    def test_shadow_0640_rejected_group_read(self):
        self.assertEqual(self._check(0o640, allowed=0o400)["result"], "취약")

    def test_non_root_owner_is_vulnerable(self):
        self.assertEqual(self._check(0o400, uid=1000, allowed=0o400)["result"], "취약")

    def test_symlink_requires_manual_check(self):
        self.assertEqual(
            self._check(0o777, file_type=stat.S_IFLNK)["result"], "수동확인"
        )

    def test_missing_file_requires_manual_check(self):
        with patch.object(Path, "lstat", side_effect=FileNotFoundError):
            self.assertEqual(
                u16._permission_result(Path("/etc/passwd"), 0o644, "U-16", "test")["result"],
                "수동확인",
            )

    @patch.object(u16.platform, "system", return_value="Windows")
    def test_u16_non_linux_not_applicable(self, _system):
        self.assertEqual(u16.check_u16_passwd_permissions()["result"], "해당없음")

    @patch.object(u18.platform, "system", return_value="Windows")
    def test_u18_non_linux_not_applicable(self, _system):
        self.assertEqual(u18.check_u18_shadow_permissions()["result"], "해당없음")

    def test_u18_does_not_read_shadow_contents(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(u18.platform, "system", return_value="Linux"))
            stack.enter_context(patch.object(u18, "_active_lines", return_value=["ID=rocky"]))
            stack.enter_context(patch.object(Path, "lstat", return_value=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o400, st_uid=0
            )))
            stack.enter_context(patch("builtins.open", side_effect=AssertionError(
                "U-18 must not read /etc/shadow contents"
            )))
            result = u18.check_u18_shadow_permissions()
        self.assertEqual(result["result"], "양호")
        self.assertNotIn("hash", str(result).lower())


if __name__ == "__main__":
    unittest.main()
