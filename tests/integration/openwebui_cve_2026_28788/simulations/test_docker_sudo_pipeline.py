"""
Focused Unit Tests for Docker Sudo-Mode Pipeline and Fail-Closed Handling.
Tests explicit sudo mode selection, absence of silent sudo invocations,
and strict fail-closed enforcement when Docker or containers are inaccessible.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

LAB_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = LAB_DIR / "scripts"

from tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence import check_docker_daemon


class TestDockerSudoPipeline(unittest.TestCase):
    """Verifies Docker CLI sudo execution controls and fail-closed safety."""

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.os.path.exists")
    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.get_command_output")
    def test_docker_daemon_check_standard_mode(self, mock_cmd, mock_exists):
        """Standard mode invokes bare 'docker info' and never invokes sudo."""
        mock_exists.return_value = True
        mock_cmd.return_value = (0, "Server Version: 29.9.3")

        res = check_docker_daemon(use_sudo=False)
        self.assertTrue(res["accessible"])
        mock_cmd.assert_called_once_with(["docker", "info"])
        self.assertNotIn("sudo", mock_cmd.call_args[0][0])

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.os.path.exists")
    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.get_command_output")
    def test_docker_daemon_check_sudo_mode_active(self, mock_cmd, mock_exists):
        """Explicit sudo mode invokes 'sudo -n docker info' non-interactively."""
        mock_exists.return_value = True
        mock_cmd.return_value = (0, "Server Version: 29.9.3")

        res = check_docker_daemon(use_sudo=True)
        self.assertTrue(res["accessible"])
        mock_cmd.assert_called_once_with(["sudo", "-n", "docker", "info"])

    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.os.path.exists")
    @patch("tests.integration.openwebui_cve_2026_28788.scripts.collect_evidence.get_command_output")
    def test_docker_daemon_check_sudo_unauthenticated_fails_closed(self, mock_cmd, mock_exists):
        """When sudo credentials are not cached, sudo -n fails closed with PERMISSION_DENIED."""
        mock_exists.return_value = True
        mock_cmd.return_value = (1, "sudo: a password is required")

        res = check_docker_daemon(use_sudo=True)
        self.assertFalse(res["accessible"])
        self.assertEqual(res["error_type"], "PERMISSION_DENIED")
        self.assertIn("password is required", res["details"])

    def test_collect_evidence_live_mode_refuses_simulated_substitutions(self):
        """Live mode must fail closed and refuse to manufacture evidence when daemon is offline."""
        env = dict(os.environ)
        env.pop("USE_SUDO", None)
        cmd = [sys.executable, str(SCRIPTS_DIR / "collect_evidence.py"), "--mode", "live"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Refusing to manufacture or substitute simulated results in live mode", res.stdout)

    def test_silent_sudo_prevention(self):
        """Standard invocation without --use-sudo or USE_SUDO never invokes sudo."""
        script_content = (SCRIPTS_DIR / "preflight.sh").read_text(encoding="utf-8")
        self.assertIn('USE_SUDO="${USE_SUDO:-0}"', script_content)
        self.assertIn('if [ "$USE_SUDO" = "1" ]; then', script_content)
        self.assertIn('DOCKER_BIN="sudo -n docker"', script_content)
        self.assertIn('DOCKER_BIN="docker"', script_content)

    def test_cleanup_script_sudo_selection(self):
        """Cleanup script supports explicit sudo mode via --use-sudo and USE_SUDO."""
        cleanup_content = (SCRIPTS_DIR / "cleanup_lab.sh").read_text(encoding="utf-8")
        self.assertIn('USE_SUDO="${USE_SUDO:-0}"', cleanup_content)
        self.assertIn('COMPOSE_CMD="sudo -n docker compose"', cleanup_content)
        self.assertIn('COMPOSE_CMD="docker compose"', cleanup_content)


if __name__ == "__main__":
    unittest.main()
