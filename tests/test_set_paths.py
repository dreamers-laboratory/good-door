#!/usr/bin/env python3
"""cmd_set must reject a bad list position with a clean error.

`elbab show`/`field` resolve JSON paths through walk(), which dies with
"no such path: ..." for a missing step. `set` traversed lists with a bare
node[int(part)], so the same typo produced a raw ValueError/IndexError
traceback instead.
"""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ELBAB = Path(__file__).resolve().parent.parent / "bin" / "elbab"


def load_elbab(homedir):
    loader = importlib.machinery.SourceFileLoader("elbab_under_test", str(ELBAB))
    spec = importlib.util.spec_from_loader("elbab_under_test", loader)
    module = importlib.util.module_from_spec(spec)
    env = {
        "ELBAB_HOME": str(homedir / ".elbab"),
        "ELBAB_USER_HOME": str(homedir),
    }
    with patch.dict(os.environ, env):
        spec.loader.exec_module(module)
    return module


class SetListPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.elbab = load_elbab(self.home)
        self.stored = {"items": ["a", "b"], "obj": {"k": "v"}}
        self.written = {}

        def fake_read(rel):
            return json.dumps(self.stored).encode()

        def fake_write(rel, data):
            self.written["data"] = json.loads(data)

        self.ctx = contextlib.ExitStack()
        self.addCleanup(self.ctx.close)
        self.ctx.enter_context(patch.object(self.elbab, "read_secret", return_value="pw"))
        self.ctx.enter_context(
            patch.object(
                self.elbab,
                "resolve",
                return_value=(Path("store.json"), Path("store.json.age")),
            )
        )
        self.ctx.enter_context(patch.object(self.elbab, "read", side_effect=fake_read))
        self.ctx.enter_context(patch.object(self.elbab, "write", side_effect=fake_write))
        self.ctx.enter_context(
            patch.object(self.elbab, "keys_lock", return_value=contextlib.nullcontext())
        )

    def run_set(self, path):
        args = SimpleNamespace(file="store.json", path=path, json=False, hidden=True)
        err = io.StringIO()
        try:
            with redirect_stderr(err):
                self.elbab.cmd_set(args)
        except SystemExit as exit:
            return exit.code, err.getvalue()
        return 0, err.getvalue()

    def test_out_of_range_index_dies_cleanly(self):
        code, err = self.run_set("items/5")
        self.assertEqual(code, 2)
        self.assertIn("no such path", err)

    def test_non_integer_index_dies_cleanly(self):
        code, err = self.run_set("items/nope")
        self.assertEqual(code, 2)
        self.assertIn("no such path", err)

    def test_valid_index_still_writes(self):
        code, _ = self.run_set("items/0")
        self.assertEqual(code, 0)
        self.assertEqual(self.written["data"]["items"], ["pw", "b"])

    def test_dict_path_still_sets(self):
        code, _ = self.run_set("obj/k")
        self.assertEqual(code, 0)
        self.assertEqual(self.written["data"]["obj"], {"k": "pw"})


if __name__ == "__main__":
    unittest.main()
