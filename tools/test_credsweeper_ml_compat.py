from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parent / "credsweeper-sidecar" / "ml_compat.py"
SPEC = importlib.util.spec_from_file_location("credsweeper_ml_compat", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OldValidator:
    def validate_groups(self, groups, batch_size):
        return groups, batch_size


class NewValidator:
    def validate_groups(self, groups, batch_size, progress_callback):
        return groups, batch_size, progress_callback


class MlCompatTests(unittest.TestCase):
    def test_old_signature(self):
        self.assertEqual(MODULE.validate_groups(OldValidator(), ["group"], 32), (["group"], 32))

    def test_new_signature_disables_progress_output(self):
        self.assertEqual(
            MODULE.validate_groups(NewValidator(), ["group"], 32),
            (["group"], 32, None),
        )


if __name__ == "__main__":
    unittest.main()
