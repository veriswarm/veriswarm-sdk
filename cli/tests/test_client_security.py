import json
import os
import tempfile
import unittest
from unittest.mock import patch

from veriswarm_cli.client import get_config, validate_api_url


class ApiUrlValidationTests(unittest.TestCase):
    def test_requires_https_for_remote_hosts(self):
        with self.assertRaises(SystemExit) as caught:
            validate_api_url("http://api.veriswarm.ai")

        self.assertIn("must be https://", str(caught.exception))

    def test_allows_https_and_normalizes_trailing_slashes(self):
        self.assertEqual(
            validate_api_url(" https://api.veriswarm.ai/// "),
            "https://api.veriswarm.ai",
        )

    def test_allows_localhost_http_for_development(self):
        self.assertEqual(
            validate_api_url("http://localhost:8000/"),
            "http://localhost:8000",
        )
        self.assertEqual(
            validate_api_url("http://127.0.0.1:8000/"),
            "http://127.0.0.1:8000",
        )

    def test_rejects_relative_urls(self):
        with self.assertRaises(SystemExit) as caught:
            validate_api_url("api.veriswarm.ai")

        self.assertIn("must be an absolute URL", str(caught.exception))

    def test_get_config_validates_environment_url_before_request(self):
        with patch.dict(
            os.environ,
            {
                "VERISWARM_API_URL": "http://attacker.example",
                "VERISWARM_API_KEY": "vsk_test",
            },
            clear=True,
        ):
            with self.assertRaises(SystemExit) as caught:
                get_config()

        self.assertIn("must be https://", str(caught.exception))

    def test_get_config_validates_saved_config(self):
        with tempfile.TemporaryDirectory() as home:
            config_dir = os.path.join(home, ".veriswarm")
            os.makedirs(config_dir)
            with open(os.path.join(config_dir, "config.json"), "w") as f:
                json.dump(
                    {
                        "api_url": "https://api.veriswarm.ai/",
                        "api_key": "vsk_test",
                    },
                    f,
                )

            with patch.dict(os.environ, {"HOME": home}, clear=True):
                self.assertEqual(
                    get_config(),
                    ("https://api.veriswarm.ai", "vsk_test"),
                )


if __name__ == "__main__":
    unittest.main()
