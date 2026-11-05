"""JSON 보고서 생성 및 민감 보고서 덮어쓰기 방지 테스트."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from contextlib import ExitStack
from unittest.mock import patch

import report_json


class ReportTests(unittest.TestCase):
    def test_build_report_summarizes_all_items(self):
        test_results = ("양호", "취약", "수동확인", "해당없음", "양호")
        fake = tuple(
            (lambda result=result, index=index: {
                "id": "U-0{}".format(index + 1),
                "name": "test",
                "result": result,
                "reason": "test",
                "details": {},
            })
            for index, result in enumerate(test_results)
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(report_json, "CHECKS", fake))
            stack.enter_context(patch.object(report_json, "get_system_info", return_value={"os": "Rocky Linux"}))
            record = report_json.build_report()
        self.assertEqual(record["item_count"], 5)
        self.assertEqual(record["summary"]["양호"], 2)
        self.assertEqual(record["summary"]["취약"], 1)
        self.assertEqual(record["summary"]["수동확인"], 1)
        self.assertEqual(record["summary"]["해당없음"], 1)
        self.assertEqual(len(record["items"]), 5)

    def test_new_private_report_and_no_overwrite(self):
        data = {"schema_version": "1.0", "items": [{"id": "U-04", "result": "양호"}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "reports" / "first.json"
            output = report_json.save_report(data, path)
            self.assertEqual(output, path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), data)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                report_json.save_report({"items": []}, path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), data)


if __name__ == "__main__":
    unittest.main()
