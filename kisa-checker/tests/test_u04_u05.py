"""U-04/U-05 계정 보안 점검 테스트. 비밀번호 해시는 출력하지 않는다."""
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from checks.u04_password_file import _summarize_passwd, check_u04_password_file
from checks.u05_unique_root_uid import _scan_uid_zero, check_u05_unique_root_uid


class U04Tests(unittest.TestCase):
    def test_shadow_and_locked_accounts(self):
        found = _summarize_passwd([
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:!:2:2:daemon:/sbin:/sbin/nologin",
        ])
        self.assertEqual(found["shadow"], 1)
        self.assertEqual(found["locked"], 1)
        self.assertEqual(found["empty"], [])

    def test_flags_empty_and_non_shadow_passwords_without_leaking_values(self):
        found = _summarize_passwd([
            "bad::1000:1000::/home/bad:/bin/bash",
            "old:$6$DO_NOT_LOG_SECRET:1001:1001::/home/old:/bin/bash",
        ])
        self.assertEqual(found["empty"], ["bad"])
        self.assertEqual(found["hash_in_passwd"], ["old"])
        self.assertNotIn("DO_NOT_LOG_SECRET", str(found))

    @patch("checks.u04_password_file.platform.system", return_value="Windows")
    def test_non_linux_not_applicable(self, _system):
        self.assertEqual(check_u04_password_file()["result"], "해당없음")

    def _check(self, passwd, shadow_present=True):
        with ExitStack() as stack:
            stack.enter_context(patch("checks.u04_password_file.platform.system", return_value="Linux"))
            read = stack.enter_context(patch("checks.u04_password_file._active_lines"))
            stack.enter_context(patch("checks.u04_password_file.Path.is_file", return_value=shadow_present))
            stack.enter_context(patch("checks.u04_password_file.Path.is_symlink", return_value=False))
            read.return_value = ["ID=rocky"]
            stack.enter_context(patch(
                "checks.u04_password_file._read_passwd_file", return_value=passwd
            ))
            return check_u04_password_file()

    def test_shadow_reference_passes(self):
        self.assertEqual(
            self._check(["root:x:0:0:root:/root:/bin/bash"])["result"], "양호"
        )

    def test_shadow_missing_is_vulnerable(self):
        self.assertEqual(
            self._check(["root:x:0:0:root:/root:/bin/bash"], False)["result"], "취약"
        )

    def test_blank_password_is_vulnerable(self):
        self.assertEqual(
            self._check(["user::1000:1000::/home/user:/bin/bash"])["result"], "취약"
        )

    def test_hash_in_passwd_requires_manual_review(self):
        self.assertEqual(
            self._check(["user:$6$fake:1000:1000::/home/user:/bin/bash"])["result"], "수동확인"
        )


class U05Tests(unittest.TestCase):
    def test_local_uid0_unique(self):
        found = _scan_uid_zero([
            "root:x:0:0:root:/root:/bin/bash",
            "user:x:1000:1000::/home/user:/bin/bash",
        ])
        self.assertEqual(found["uid0_accounts"], ["root"])

    def test_non_root_uid0_detection(self):
        found = _scan_uid_zero([
            "root:x:0:0:root:/root:/bin/bash",
            "admin:x:0:0::/home/admin:/bin/bash",
        ])
        self.assertEqual(found["uid0_accounts"], ["root", "admin"])

    @patch("checks.u05_unique_root_uid.platform.system", return_value="Windows")
    def test_non_linux_not_applicable(self, _system):
        self.assertEqual(check_u05_unique_root_uid()["result"], "해당없음")

    def _check(self, lines):
        with ExitStack() as stack:
            stack.enter_context(patch("checks.u05_unique_root_uid.platform.system", return_value="Linux"))
            stack.enter_context(patch("checks.u05_unique_root_uid._active_lines", return_value=["ID=rocky"]))
            stack.enter_context(patch("checks.u05_unique_root_uid._read_passwd", return_value=lines))
            return check_u05_unique_root_uid()

    def test_unique_root_passes_locally(self):
        self.assertEqual(self._check(["root:x:0:0:root:/root:/bin/bash"])["result"], "양호")

    def test_alias_is_vulnerable(self):
        result = self._check([
            "root:x:0:0:root:/root:/bin/bash",
            "admin:x:0:1000::/home/admin:/bin/bash",
        ])
        self.assertEqual(result["result"], "취약")
        self.assertIn("admin", result["reason"])

    def test_missing_root_requires_review(self):
        self.assertEqual(self._check(["admin:x:1000:1000::/home/admin:/bin/bash"])["result"], "수동확인")


if __name__ == "__main__":
    unittest.main()
