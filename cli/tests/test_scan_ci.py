import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from veriswarm_cli import main as cli_main


class ScanCiCommandTests(unittest.TestCase):
    def test_builds_scan_payload_with_glob_deduplication_and_diff(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with open("ci.yml", "w", encoding="utf-8") as f:
                    f.write("jobs:\n  test:\n    steps: []\n")

                with (
                    mock.patch.object(cli_main, "api_request") as api_request,
                    mock.patch.object(cli_main, "_ci_git_diff", return_value="diff-body") as git_diff,
                    contextlib.redirect_stdout(io.StringIO()) as stdout,
                ):
                    api_request.return_value = {
                        "findings": [],
                        "highest_severity": "none",
                        "blocked": False,
                        "enforcement_level": "warn",
                    }

                    cli_main.cmd_scan_ci(["*.yml", "ci.yml", "--base", "main"])
            finally:
                os.chdir(old_cwd)

        git_diff.assert_called_once_with("ci.yml", "main")
        api_request.assert_called_once()
        endpoint = api_request.call_args.args[0]
        kwargs = api_request.call_args.kwargs
        self.assertEqual(endpoint, "/v1/suite/guard/scan-ci")
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(
            kwargs["body"],
            {
                "files": [
                    {
                        "path": "ci.yml",
                        "content": "jobs:\n  test:\n    steps: []\n",
                        "diff": "diff-body",
                    }
                ]
            },
        )
        self.assertIn("Scanning 1 file(s)", stdout.getvalue())

    def test_exits_nonzero_when_scan_result_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow_path = os.path.join(tmpdir, "ci.yml")
            with open(workflow_path, "w", encoding="utf-8") as f:
                f.write("jobs:\n  release:\n    steps: []\n")

            with (
                mock.patch.object(cli_main, "api_request") as api_request,
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                api_request.return_value = {
                    "findings": [
                        {
                            "severity": "high",
                            "check": "secret-egress",
                            "layer": "layer2",
                            "path": "ci.yml",
                            "line": 7,
                            "recommendation": "Remove outbound secret transfer.",
                        }
                    ],
                    "highest_severity": "high",
                    "blocked": True,
                    "enforcement_level": "block",
                }

                with self.assertRaises(SystemExit) as caught:
                    cli_main.cmd_scan_ci([workflow_path])

        self.assertEqual(caught.exception.code, 1)
        api_request.assert_called_once()
        output = stdout.getvalue()
        self.assertIn("[HIGH]", output)
        self.assertIn("secret-egress", output)
        self.assertIn("Blocked:", output)
        self.assertIn("TRUE", output)


if __name__ == "__main__":
    unittest.main()
