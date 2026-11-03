from __future__ import annotations

import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock


CHECK_PATH = pathlib.Path(__file__).with_name("check.py")


def load_check_module(env=None):
    spec = importlib.util.spec_from_file_location("veriswarm_action_check", CHECK_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    module_env = {
        "VERISWARM_API_URL": "https://api.veriswarm.ai",
        "VERISWARM_API_ALLOWED_HOSTS": "api.veriswarm.ai",
    }
    if env:
        module_env.update(env)
    with mock.patch.dict(os.environ, module_env, clear=False):
        spec.loader.exec_module(module)
    return module


class ApiBoundaryTests(unittest.TestCase):
    def test_rejects_insecure_api_url_at_import(self):
        with self.assertRaises(SystemExit) as caught:
            load_check_module({"VERISWARM_API_URL": "http://api.veriswarm.ai"})

        self.assertIn("must be https://", str(caught.exception))

    def test_rejects_api_url_host_outside_allowlist_at_import(self):
        with self.assertRaises(SystemExit) as caught:
            load_check_module(
                {
                    "VERISWARM_API_URL": "https://attacker.example",
                    "VERISWARM_API_ALLOWED_HOSTS": "api.veriswarm.ai",
                }
            )

        message = str(caught.exception)
        self.assertIn("not in allowlist", message)
        self.assertIn("attacker.example", message)

    def test_allows_explicit_self_hosted_api_url(self):
        module = load_check_module(
            {
                "VERISWARM_API_URL": "https://veriswarm.internal/",
                "VERISWARM_API_ALLOWED_HOSTS": "api.veriswarm.ai, veriswarm.internal",
            }
        )

        self.assertEqual(module.API_URL, "https://veriswarm.internal")

    def test_redirect_handler_strips_auth_headers(self):
        module = load_check_module()
        request = module.Request(
            "https://api.veriswarm.ai/v1/check",
            headers={
                "x-api-key": "secret-key",
                "Authorization": "Bearer secret-token",
                "X-Trace-Id": "trace-1",
            },
            method="GET",
        )

        redirected = module._StripAuthRedirectHandler().redirect_request(
            request,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="https://attacker.example/steal",
        )

        self.assertIsNotNone(redirected)
        redirected_headers = {k.lower(): v for k, v in redirected.headers.items()}
        self.assertNotIn("x-api-key", redirected_headers)
        self.assertNotIn("authorization", redirected_headers)
        self.assertEqual(redirected_headers["x-trace-id"], "trace-1")

    def test_set_output_sanitizes_value_injection(self):
        module = load_check_module()

        with tempfile.TemporaryDirectory() as tmp:
            output_path = pathlib.Path(tmp, "github-output")
            module.GITHUB_OUTPUT = str(output_path)

            module.set_output("summary", "ok\nMALICIOUS=value\rnext\x00null")

            self.assertEqual(
                output_path.read_text(encoding="utf-8"),
                "summary=ok MALICIOUS=valuenextnull\n",
            )


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
