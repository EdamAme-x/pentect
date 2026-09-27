import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("plugin_setup", Path(__file__).parents[1] / "setup.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

class SetupTests(unittest.TestCase):
    def test_offline_probe_does_not_mutate_approved_file_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(setup, "ROOT", root), patch.object(setup.os, "chdir"), \
                 patch.object(setup, "run") as run, patch.object(sys, "argv", ["setup", "--prepare", "--profile", "cpu"]), \
                 patch.dict(os.environ), patch.dict(sys.modules, {"huggingface_hub": Mock(), "gliner": Mock()}):
                setup.main()
                argv = run.call_args.args[0]
                self.assertEqual(argv[1:3], ["-B", "-c"])
                self.assertEqual(os.environ["HF_HUB_OFFLINE"], "1")
                self.assertEqual(json.loads((root / "setup.json").read_text())["device"], "cpu")

if __name__ == "__main__":
    unittest.main()

