from setuptools import setup, find_packages

setup(
    name="veriswarm-cli",
    version="0.1.0",
    description="VeriSwarm CLI — trust scoring, event ingestion, agent testing, and Guard scanning from the terminal.",
    author="VeriSwarm",
    author_email="support@veriswarm.ai",
    url="https://github.com/veriswarm/veriswarm-ai",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[],  # Zero dependencies — uses stdlib urllib only
    entry_points={
        "console_scripts": [
            "veriswarm=veriswarm_cli.main:main",
        ],
    },
)
