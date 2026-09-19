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


class GateApiErrorHandlingTests(unittest.TestCase):
    def setUp(self):
        self.module = load_check_module()
        self.module.failures.clear()
        self.module.summary_lines.clear()
        self.module.AGENT_ID = "agt_test"
        self.module.api_request = mock.Mock(return_value={"error": "API 503"})

    def test_score_api_error_fails_when_min_trust_score_enforced(self):
        self.module.MIN_TRUST_SCORE = 80

        self.module.check_score()

        self.assertEqual(
            self.module.failures,
            ["Trust score check could not be evaluated: API 503"],
        )

    def test_score_api_error_warns_when_min_trust_score_disabled(self):
        self.module.MIN_TRUST_SCORE = 0

        self.module.check_score()

        self.assertEqual(self.module.failures, [])

    def test_decision_api_error_fails_when_fail_on_deny_enabled(self):
        self.module.FAIL_ON_DENY = True

        self.module.check_decision()

        self.assertEqual(
            self.module.failures,
            ["Trust decision check could not be evaluated: API 503"],
        )

    def test_security_test_api_error_fails_when_readiness_gate_enabled(self):
        self.module.FAIL_ON_LOW_SCORE = 70

        self.module.check_test()

        self.assertEqual(
            self.module.failures,
            ["Security test check could not be evaluated: API 503"],
        )

    def test_owasp_api_error_fails_when_coverage_gate_enabled(self):
        self.module.MIN_OWASP_COVERAGE = 0.9

        self.module.check_owasp()

        self.assertEqual(
            self.module.failures,
            ["OWASP attestation check could not be evaluated: API 503"],
        )


if __name__ == "__main__":
    unittest.main()
