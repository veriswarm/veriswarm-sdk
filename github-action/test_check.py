from __future__ import annotations

import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock


CHECK_PATH = pathlib.Path(__file__).with_name("check.py")


def load_check_module():
    spec = importlib.util.spec_from_file_location("veriswarm_action_check", CHECK_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CiExfilErrorHandlingTests(unittest.TestCase):
    def setUp(self):
        self.module = load_check_module()
        self.module.failures.clear()
        self.module.summary_lines.clear()

    def _workspace_with_workflow(self):
        tmp = tempfile.TemporaryDirectory()
        workflow_dir = pathlib.Path(tmp.name, ".github", "workflows")
        workflow_dir.mkdir(parents=True)
        workflow_dir.joinpath("build.yml").write_text(
            "name: build\non: [push]\njobs: {}\n",
            encoding="utf-8",
        )
        self.addCleanup(tmp.cleanup)
        return tmp.name

    def test_ci_exfil_api_error_fails_closed_when_enforced(self):
        workspace = self._workspace_with_workflow()
        self.module.FAIL_ON_CI_EXFIL = True
        self.module.api_request = mock.Mock(return_value={"error": "API 500"})

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": workspace}, clear=False):
            self.module.check_ci_exfil()

        self.assertEqual(len(self.module.failures), 1)
        self.assertIn("could not be evaluated: API 500", self.module.failures[0])

    def test_ci_exfil_api_error_can_warn_when_not_enforced(self):
        workspace = self._workspace_with_workflow()
        self.module.FAIL_ON_CI_EXFIL = False
        self.module.api_request = mock.Mock(return_value={"error": "API 500"})

        with mock.patch.dict(os.environ, {"GITHUB_WORKSPACE": workspace}, clear=False):
            self.module.check_ci_exfil()

        self.assertEqual(self.module.failures, [])


if __name__ == "__main__":
    unittest.main()
