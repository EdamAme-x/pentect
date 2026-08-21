import importlib.util
from pathlib import Path
import platform
import unittest
from unittest import mock


SETUP_PATH = Path(__file__).parents[1] / "setup.py"
SPEC = importlib.util.spec_from_file_location("pentect_opf_setup", SETUP_PATH)
SETUP = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(SETUP)


class SetupTests(unittest.TestCase):
    def test_cpu_profile_uses_official_cpu_index(self) -> None:
        with (
            mock.patch.object(SETUP, "nvidia_driver_major", return_value=600),
            mock.patch.object(SETUP.platform, "system", return_value="Linux"),
            mock.patch.object(SETUP.platform, "machine", return_value="x86_64"),
        ):
            plan = SETUP.build_plan("cpu", {})
        self.assertEqual(plan["device"], "cpu")
        self.assertEqual(plan["torch_index"], "https://download.pytorch.org/whl/cpu")

    @unittest.skipIf(platform.system() == "Darwin", "CUDA is intentionally unavailable on macOS")
    def test_auto_profile_selects_cuda_wheel_from_driver(self) -> None:
        with (
            mock.patch.object(SETUP, "nvidia_driver_major", return_value=579),
            mock.patch.object(SETUP.platform, "machine", return_value="x86_64"),
        ):
            self.assertEqual(SETUP.build_plan("auto", {})["torch_wheel"], "cu126")
        with (
            mock.patch.object(SETUP, "nvidia_driver_major", return_value=580),
            mock.patch.object(SETUP.platform, "machine", return_value="x86_64"),
        ):
            self.assertEqual(SETUP.build_plan("auto", {})["torch_wheel"], "cu130")

    def test_macos_uses_the_official_default_pytorch_package(self) -> None:
        with (
            mock.patch.object(SETUP, "nvidia_driver_major", return_value=None),
            mock.patch.object(SETUP.platform, "system", return_value="Darwin"),
        ):
            plan = SETUP.build_plan("auto", {})
        self.assertEqual(plan["device"], "cpu")
        self.assertEqual(plan["torch_wheel"], "macos")
        self.assertIsNone(plan["torch_index"])

    def test_arm_does_not_select_an_unsupported_cuda_index(self) -> None:
        with (
            mock.patch.object(SETUP, "nvidia_driver_major", return_value=600),
            mock.patch.object(SETUP.platform, "system", return_value="Linux"),
            mock.patch.object(SETUP.platform, "machine", return_value="aarch64"),
        ):
            plan = SETUP.build_plan("auto", {})
        self.assertEqual(plan["device"], "cpu")

    def test_auto_profile_falls_back_to_cpu_without_nvidia(self) -> None:
        with mock.patch.object(SETUP, "nvidia_driver_major", return_value=None):
            plan = SETUP.build_plan("auto", {})
        self.assertEqual(plan["device"], "cpu")

    def test_keep_preserves_manual_profile(self) -> None:
        state = {"requested_profile": "cpu"}
        with mock.patch.object(SETUP, "nvidia_driver_major", return_value=600):
            plan = SETUP.build_plan("keep", state)
        self.assertEqual(plan["requested_profile"], "cpu")
        self.assertEqual(plan["device"], "cpu")

    def test_explicit_cuda_fails_without_driver(self) -> None:
        with mock.patch.object(SETUP, "nvidia_driver_major", return_value=None):
            with self.assertRaises(RuntimeError):
                SETUP.build_plan("cuda", {})

    def test_fixture_is_limited_to_explicit_or_official_release_ci(self) -> None:
        with mock.patch.dict(
            SETUP.os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_WORKFLOW": "Release",
                "GITHUB_REPOSITORY": "EdamAme-x/pentect",
            },
            clear=True,
        ):
            self.assertTrue(SETUP.controlled_fixture())
        with mock.patch.dict(
            SETUP.os.environ,
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_WORKFLOW": "Release",
                "GITHUB_REPOSITORY": "someone/fork",
            },
            clear=True,
        ):
            self.assertFalse(SETUP.controlled_fixture())


if __name__ == "__main__":
    unittest.main()
