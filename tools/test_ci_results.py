import unittest

from tools.check_ci_results import EXPECTED_JOBS, failed_jobs


def payload(result: str = "success") -> dict[str, dict[str, str]]:
    return {name: {"result": result} for name in EXPECTED_JOBS}


class CiGateTests(unittest.TestCase):
    def test_all_success_passes(self) -> None:
        self.assertEqual(failed_jobs(payload()), [])

    def test_optional_skips_pass(self) -> None:
        needs = payload()
        for name in EXPECTED_JOBS - {"changes", "test"}:
            needs[name]["result"] = "skipped"
        self.assertEqual(failed_jobs(needs), [])

    def test_platform_failure_blocks(self) -> None:
        needs = payload()
        needs["app-platform"]["result"] = "failure"
        self.assertEqual(failed_jobs(needs), ["app-platform: failure"])

    def test_missing_job_blocks(self) -> None:
        needs = payload()
        del needs["native-ocr"]
        self.assertEqual(failed_jobs(needs), ["native-ocr: missing"])

    def test_change_detection_may_not_skip(self) -> None:
        needs = payload()
        needs["changes"]["result"] = "skipped"
        self.assertEqual(failed_jobs(needs), ["changes: skipped"])


if __name__ == "__main__":
    unittest.main()
