"""선정 항목과 JSON 보고서 등록 상태의 회귀 검증."""
import unittest
from contextlib import ExitStack
from unittest.mock import patch

import report_json


class RegistryTests(unittest.TestCase):
    def test_eight_selected_checkers_registered_in_expected_order(self):
        self.assertEqual(
            [fn.__name__ for fn in report_json.CHECKS],
            [
                "check_u01_combined",
                "check_u02_password_policy",
                "check_u03_account_lockout",
                "check_u04_password_file",
                "check_u05_unique_root_uid",
                "check_u06_su_restriction",
                "check_u16_passwd_permissions",
                "check_u18_shadow_permissions",
            ],
        )

    def test_json_report_summary_counts_eight_items(self):
        statuses = ("양호", "취약", "수동확인", "양호",
                    "해당없음", "수동확인", "양호", "취약")
        fake_checkers = tuple(
            (lambda index=index, status=status: {
                "id": "TEST-{}".format(index + 1),
                "name": "mock",
                "result": status,
                "reason": "mock-only",
                "details": {},
            })
            for index, status in enumerate(statuses)
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(report_json, "CHECKS", fake_checkers))
            stack.enter_context(patch.object(
                report_json, "get_system_info", return_value={"os": "mock"}
            ))
            report = report_json.build_report()

        self.assertEqual(report["item_count"], 8)
        self.assertEqual(report["summary"], {
            "양호": 3, "취약": 2, "수동확인": 2, "해당없음": 1
        })
        self.assertIn("U-16", report["scope"])
        self.assertIn("U-18", report["scope"])
        self.assertEqual(len(report["items"]), 8)


if __name__ == "__main__":
    unittest.main()
