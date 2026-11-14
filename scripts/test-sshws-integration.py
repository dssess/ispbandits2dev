#!/usr/bin/env python3
"""Run the loopback integration tests for the implemented HTTP Custom SSH relay.

The former Nginx-to-websockify `/sshws` harness targeted an alpha-4 topology that
is no longer supported. Current alpha-6 uses a dedicated HTTP Custom relay to the
existing local OpenSSH daemon; its end-to-end protocol tests run against a dummy
loopback backend and never touch a VPS, public port, or system configuration.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    env = os.environ.copy()
    source = str(ROOT / "src")
    env["PYTHONPATH"] = source + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(ROOT / "tests"),
            "-p",
            "test_ssh_http_proxy.py",
            "-v",
        ],
        cwd=ROOT,
        env=env,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
