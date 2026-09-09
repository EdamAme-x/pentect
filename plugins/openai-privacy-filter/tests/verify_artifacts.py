#!/usr/bin/env python3
"""Refuse to publish OPF live-smoke logs containing fixture plaintext."""

import importlib.util
from pathlib import Path
import os


LIVE_PATH = Path(__file__).with_name("live_e2e.py")
SPEC = importlib.util.spec_from_file_location("pentect_opf_live_e2e", LIVE_PATH)
assert SPEC is not None and SPEC.loader is not None
LIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIVE)
LIVE.assert_value_free_logs(os.environ, must_exist=True)
