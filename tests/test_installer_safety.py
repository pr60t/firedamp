#!/usr/bin/env python3
"""
Unit and regression tests for install.sh safety, signal handling, and atomic no-clobber publication.
"""

import errno
import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"


class TestInstallScriptSafety(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="firedamp-install-test-")
        self.home_dir = os.path.join(self.test_dir, "fake_home")
        os.makedirs(self.home_dir, mode=0o755, exist_ok=True)
        os.chmod(self.home_dir, 0o755)
        self.install_dir = os.path.join(self.home_dir, ".firedamp")
        self.bin_dir = os.path.join(self.home_dir, ".local", "bin")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run_installer(self, env_overrides=None, cwd=None):
        env = os.environ.copy()
        env["HOME"] = self.home_dir
        env["FIREDAMP_INSTALL_DIR"] = self.install_dir
        env["FIREDAMP_BIN_DIR"] = self.bin_dir
        if env_overrides:
            env.update(env_overrides)

        res = subprocess.run(
            ["bash", str(INSTALL_SH)],
            cwd=cwd or str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
        )
        return res

    def test_existing_non_git_destination_refused_data_preserved(self):
        """Existing non-Git destination containing user data: installation refuses; data remains unchanged."""
        os.makedirs(self.install_dir, exist_ok=True)
        secret_file = os.path.join(self.install_dir, "my_precious_data.txt")
        with open(secret_file, "w") as f:
            f.write("DO_NOT_DELETE_ME")

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already exists", res.stderr + res.stdout)

        # Verify data is byte-for-byte intact
        self.assertTrue(os.path.isfile(secret_file))
        with open(secret_file, "r") as f:
            self.assertEqual(f.read(), "DO_NOT_DELETE_ME")

    def test_existing_git_checkout_with_uncommitted_changes_refused(self):
        """Existing Git checkout with uncommitted changes: installation refuses; checkout unchanged."""
        os.makedirs(self.install_dir, exist_ok=True)
        os.makedirs(os.path.join(self.install_dir, ".git"), exist_ok=True)
        dirty_file = os.path.join(self.install_dir, "uncommitted_work.py")
        with open(dirty_file, "w") as f:
            f.write("# important local edits")

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("already exists", res.stderr + res.stdout)
        self.assertTrue(os.path.isfile(dirty_file))
        with open(dirty_file, "r") as f:
            self.assertEqual(f.read(), "# important local edits")

    def test_symlink_destination_refused(self):
        """Symlink destination: installation refuses."""
        target_dir = os.path.join(self.test_dir, "symlink_target")
        os.makedirs(target_dir, exist_ok=True)
        os.symlink(target_dir, self.install_dir)

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Target install path is a symlink", res.stderr + res.stdout)

    def test_unsafe_destination_paths_refused(self):
        """Critical or unsafe paths like / or /tmp or $HOME are rejected."""
        res = self._run_installer(env_overrides={"FIREDAMP_INSTALL_DIR": self.home_dir})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Unsafe target install path", res.stderr + res.stdout)

    def test_staging_cleanup_on_failure(self):
        """Staging directory is cleanly removed if an error occurs during installation."""
        broken_bin_dir = os.path.join(self.test_dir, "broken_bin")
        os.makedirs(broken_bin_dir, exist_ok=True)
        with open(os.path.join(broken_bin_dir, "git"), "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(broken_bin_dir, "git"), 0o755)

        path_with_broken = f"{broken_bin_dir}:{os.environ.get('PATH', '')}"
        res = self._run_installer(env_overrides={"PATH": path_with_broken})
        self.assertNotEqual(res.returncode, 0)

        # Ensure no staging directory was left behind in parent dir
        staging_parent = Path(self.install_dir).parent
        staging_dirs = [d for d in os.listdir(staging_parent) if "firedamp-install-staging" in d]
        self.assertEqual(len(staging_dirs), 0, f"Found leaked staging directories: {staging_dirs}")

    def test_destination_collision_pre_execution(self):
        """If destination already exists, installer refuses to overwrite."""
        os.makedirs(self.install_dir, exist_ok=True)
        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertNotIn("[+] Firedamp successfully installed", res.stdout)

    def _create_clean_local_repo(self, name="clean_repo"):
        repo_dir = os.path.join(self.test_dir, name)
        os.makedirs(os.path.join(repo_dir, "core"), exist_ok=True)
        with open(os.path.join(repo_dir, "pyproject.toml"), "w") as f:
            f.write('[project]\nname = "firedamp"\nversion = "0.1.0"\n')
        with open(os.path.join(repo_dir, "cli.py"), "w") as f:
            f.write('print("firedamp")\n')
        with open(os.path.join(repo_dir, "core", "__init__.py"), "w") as f:
            f.write("")
        subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo_dir, check=True)
        return repo_dir

    def _create_mocked_installer(self, pause_code, pause_marker='# 10. Atomic / no-clobber publication to TARGET_INSTALL_DIR\n'):
        with open(INSTALL_SH, "r") as f:
            content = f.read()

        self.assertIn(pause_marker, content)
        instrumented = content.replace(pause_marker, pause_marker + pause_code, 1)
        # Mock network/pip operations and verification checks in unit-test sandbox
        mock_pip = (
            'echo "mock pip success" && '
            'mkdir -p "${VENV_DIR}/bin" && '
            'printf "#!/bin/sh\\necho firedamp 0.1.0\\n" > "${VENV_DIR}/bin/firedamp" && '
            'chmod +x "${VENV_DIR}/bin/firedamp" && '
            'SITE_PKGS=$("${VENV_DIR}/bin/python" -c "import site; print(site.getsitepackages()[0])") && '
            'mkdir -p "${SITE_PKGS}/firedamp-0.1.0.dist-info" && '
            'printf "Metadata-Version: 2.1\\nName: firedamp\\nVersion: 0.1.0\\n" > "${SITE_PKGS}/firedamp-0.1.0.dist-info/METADATA"'
        )
        instrumented = instrumented.replace(
            '"${VENV_DIR}/bin/pip" install "${PIP_INSTALL_FLAGS[@]}"',
            mock_pip
        )
        instrumented = instrumented.replace(
            'if ! "${VENV_DIR}/bin/python" -c "import cli; import core; import probes" >/dev/null 2>&1; then',
            'if false; then'
        )
        instrumented = instrumented.replace(
            'if ! "$LAUNCHER" version >/dev/null 2>&1; then',
            'if false; then'
        )
        script_path = os.path.join(self.test_dir, f"mock_install_{time.time_ns()}.sh")
        with open(script_path, "w") as f:
            f.write(instrumented)
        os.chmod(script_path, 0o755)
        return script_path

    def _run_concurrent_collision_test(self, setup_collision_fn, verify_collision_fn):
        sync_file = os.path.join(self.test_dir, f"sync_{time.time_ns()}")
        resume_file = os.path.join(self.test_dir, f"resume_{time.time_ns()}")
        clean_repo = self._create_clean_local_repo()

        pause_code = f"""
touch "{sync_file}"
while [ ! -f "{resume_file}" ]; do
    sleep 0.02
done
"""
        script_path = self._create_mocked_installer(pause_code)

        env = os.environ.copy()
        env["HOME"] = self.home_dir
        env["FIREDAMP_INSTALL_DIR"] = self.install_dir
        env["FIREDAMP_BIN_DIR"] = self.bin_dir

        proc = subprocess.Popen(
            ["bash", script_path],
            cwd=clean_repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        start_time = time.time()
        while not os.path.exists(sync_file):
            time.sleep(0.02)
            if time.time() - start_time > 15:
                proc.kill()
                out, err = proc.communicate()
                self.fail(f"Timeout waiting for sync hook. stdout={out}, stderr={err}")

        # Destination must not exist yet
        self.assertFalse(os.path.exists(self.install_dir))

        # Invoke collision setup function
        setup_collision_fn(self.install_dir)

        # Resume installer
        with open(resume_file, "w") as f:
            f.write("go")

        stdout, stderr = proc.communicate(timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Refusing to overwrite", stderr + stdout)
        self.assertNotIn("Firedamp successfully installed", stdout)

        # Verify destination integrity
        verify_collision_fn(self.install_dir)

        # Verify staging directory cleanup
        staging_parent = Path(self.install_dir).parent
        staging_dirs = [d for d in os.listdir(staging_parent) if "firedamp-install-staging" in d]
        self.assertEqual(len(staging_dirs), 0, f"Found leaked staging directories: {staging_dirs}")

    def test_concurrent_collision_race_with_populated_destination(self):
        """Deterministic test: destination created concurrently with sentinel file before publication."""
        sentinel_bytes = b"\xde\xad\xbe\xefSENTINEL_POPULATED_DATA_98765\x00\x01\x02\x03"
        expected_digest = hashlib.sha256(sentinel_bytes).hexdigest()

        def setup(dst):
            os.makedirs(dst, exist_ok=True)
            with open(os.path.join(dst, "sentinel.bin"), "wb") as f:
                f.write(sentinel_bytes)

        def verify(dst):
            sentinel_path = os.path.join(dst, "sentinel.bin")
            self.assertTrue(os.path.isfile(sentinel_path))
            with open(sentinel_path, "rb") as f:
                actual_bytes = f.read()
            self.assertEqual(actual_bytes, sentinel_bytes)
            self.assertEqual(hashlib.sha256(actual_bytes).hexdigest(), expected_digest)
            self.assertEqual(os.listdir(dst), ["sentinel.bin"])

        self._run_concurrent_collision_test(setup, verify)

    def test_concurrent_collision_race_with_empty_directory(self):
        """Deterministic test: destination created concurrently as an empty directory."""
        def setup(dst):
            os.makedirs(dst, exist_ok=True)

        def verify(dst):
            self.assertTrue(os.path.isdir(dst))
            self.assertEqual(os.listdir(dst), [])

        self._run_concurrent_collision_test(setup, verify)

    def test_concurrent_collision_race_with_file_destination(self):
        """Deterministic test: destination created concurrently as a regular file."""
        file_content = "REGULAR_FILE_CONTENT_OCCUPYING_TARGET"

        def setup(dst):
            with open(dst, "w") as f:
                f.write(file_content)

        def verify(dst):
            self.assertTrue(os.path.isfile(dst))
            with open(dst, "r") as f:
                self.assertEqual(f.read(), file_content)

        self._run_concurrent_collision_test(setup, verify)

    def test_concurrent_collision_race_with_symlink_destination(self):
        """Deterministic test: destination created concurrently as a symlink."""
        target_dir = os.path.join(self.test_dir, "concurrent_symlink_target")
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "original.txt"), "w") as f:
            f.write("ORIGINAL_TARGET_FILE")

        def setup(dst):
            os.symlink(target_dir, dst)

        def verify(dst):
            self.assertTrue(os.path.islink(dst))
            self.assertEqual(os.readlink(dst), target_dir)
            self.assertEqual(os.listdir(target_dir), ["original.txt"])

        self._run_concurrent_collision_test(setup, verify)

    def test_successful_publication_when_destination_absent(self):
        """Successful publication: both destinations are atomically created and contain expected structure."""
        clean_repo = self._create_clean_local_repo()
        script_path = self._create_mocked_installer("")

        env = os.environ.copy()
        env["HOME"] = self.home_dir
        env["FIREDAMP_INSTALL_DIR"] = self.install_dir
        env["FIREDAMP_BIN_DIR"] = self.bin_dir

        proc = subprocess.run(
            ["bash", script_path],
            cwd=clean_repo,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, f"Installer failed: stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertTrue(os.path.isdir(self.install_dir))
        self.assertTrue(os.path.isdir(os.path.join(self.install_dir, "repo")))
        self.assertTrue(os.path.isdir(os.path.join(self.install_dir, "venv")))
        self.assertIn("Firedamp 0.1.0 successfully installed", proc.stdout)

        # Check launcher created as regular executable file (not symlink)
        launcher = os.path.join(self.bin_dir, "firedamp")
        self.assertTrue(os.path.isfile(launcher))
        self.assertFalse(os.path.islink(launcher))
        self.assertTrue(os.access(launcher, os.X_OK))

    def test_sigint_and_sigterm_cleanup(self):
        """Verify that SIGINT and SIGTERM immediately terminate the installer and clean up staging."""
        clean_repo = self._create_clean_local_repo()
        for sig in [signal.SIGINT, signal.SIGTERM]:
            sync_file = os.path.join(self.test_dir, f"sync_sig_{sig}")
            pause_code = f"""
touch "{sync_file}"
while true; do
    sleep 0.02
done
"""
            script_path = self._create_mocked_installer(pause_code)

            env = os.environ.copy()
            env["HOME"] = self.home_dir
            env["FIREDAMP_INSTALL_DIR"] = self.install_dir
            env["FIREDAMP_BIN_DIR"] = self.bin_dir

            proc = subprocess.Popen(
                ["bash", script_path],
                cwd=clean_repo,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            start_time = time.time()
            while not os.path.exists(sync_file):
                time.sleep(0.02)
                if time.time() - start_time > 15:
                    proc.kill()
                    out, err = proc.communicate()
                    self.fail(f"Timeout waiting for signal pause. stdout={out}, stderr={err}")

            staging_parent = Path(self.install_dir).parent
            staging_dirs_active = [d for d in os.listdir(staging_parent) if "firedamp-install-staging" in d]
            self.assertEqual(len(staging_dirs_active), 1)

            proc.send_signal(sig)
            stdout, stderr = proc.communicate(timeout=10)

            self.assertNotEqual(proc.returncode, 0)

            staging_dirs_after = [d for d in os.listdir(staging_parent) if "firedamp-install-staging" in d]
            self.assertEqual(len(staging_dirs_after), 0, f"Signal {sig} failed to clean up staging: {staging_dirs_after}")

    def test_destination_not_altered_when_parent_permissions_restricted(self):
        """Destination not altered when parent directory permissions are restricted."""
        restricted_parent = os.path.join(self.test_dir, "restricted_parent")
        os.makedirs(restricted_parent, exist_ok=True)
        dest = os.path.join(restricted_parent, ".firedamp")
        os.makedirs(dest, exist_ok=True)
        sentinel_file = os.path.join(dest, "preserve.bin")
        content = b"\x00\xff\xfe\xfdRESTRICTED_DATA_TEST"
        with open(sentinel_file, "wb") as f:
            f.write(content)
        digest_before = hashlib.sha256(content).hexdigest()

        os.chmod(restricted_parent, 0o555)
        try:
            res = self._run_installer(env_overrides={"FIREDAMP_INSTALL_DIR": dest})
            self.assertNotEqual(res.returncode, 0)
        finally:
            os.chmod(restricted_parent, 0o755)

        with open(sentinel_file, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest_before)

    # --- Launcher Security & Partial Installation Tests (Section 2.4) ---

    def test_existing_launcher_regular_file_refused_and_preserved(self):
        """Existing launcher regular file with sentinel content is never overwritten or truncated."""
        os.makedirs(self.bin_dir, exist_ok=True)
        launcher = os.path.join(self.bin_dir, "firedamp")
        sentinel = b"#!/bin/sh\n# USER_CUSTOM_LAUNCHER_SENTINEL\n"
        with open(launcher, "wb") as f:
            f.write(sentinel)
        digest = hashlib.sha256(sentinel).hexdigest()

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Launcher destination already exists", res.stderr + res.stdout)
        self.assertNotIn("successfully installed", res.stdout)
        with open(launcher, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)

    def test_existing_launcher_symlink_refused_and_target_preserved(self):
        """Existing launcher symlink is never followed and its target file is preserved byte-for-byte."""
        os.makedirs(self.bin_dir, exist_ok=True)
        target_file = os.path.join(self.test_dir, "victim_target.txt")
        sentinel = b"CRITICAL_USER_DATA_SYMLINK_TARGET_999"
        with open(target_file, "wb") as f:
            f.write(sentinel)
        digest = hashlib.sha256(sentinel).hexdigest()

        launcher = os.path.join(self.bin_dir, "firedamp")
        os.symlink(target_file, launcher)

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Launcher path is a symlink", res.stderr + res.stdout)
        self.assertTrue(os.path.islink(launcher))
        with open(target_file, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)

    def test_existing_launcher_directory_refused(self):
        """Existing directory at launcher path is refused without modification."""
        os.makedirs(self.bin_dir, exist_ok=True)
        launcher = os.path.join(self.bin_dir, "firedamp")
        os.makedirs(launcher, exist_ok=True)
        with open(os.path.join(launcher, "keep.txt"), "w") as f:
            f.write("KEEP")

        res = self._run_installer()
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(os.path.isdir(launcher))
        self.assertEqual(os.listdir(launcher), ["keep.txt"])

    def test_launcher_parent_symlink_refused(self):
        """Symlink at BIN_DIR or parent directory of BIN_DIR is refused."""
        real_bin = os.path.join(self.test_dir, "real_bin")
        os.makedirs(real_bin, exist_ok=True)
        symlink_bin = os.path.join(self.home_dir, "symlink_bin")
        os.symlink(real_bin, symlink_bin)

        res = self._run_installer(env_overrides={"FIREDAMP_BIN_DIR": symlink_bin})
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("symlink", (res.stderr + res.stdout).lower())
        self.assertEqual(os.listdir(real_bin), [])

    def test_unsafe_launcher_directory_permissions_refused(self):
        """World-writable or read-only BIN_DIR is refused before installation."""
        world_writable = os.path.join(self.test_dir, "ww_bin")
        os.makedirs(world_writable, exist_ok=True)
        os.chmod(world_writable, 0o777)
        try:
            res = self._run_installer(env_overrides={"FIREDAMP_BIN_DIR": world_writable})
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("world-writable", (res.stderr + res.stdout).lower())
        finally:
            os.chmod(world_writable, 0o755)

        readonly_bin = os.path.join(self.test_dir, "ro_bin")
        os.makedirs(readonly_bin, exist_ok=True)
        os.chmod(readonly_bin, 0o555)
        try:
            res = self._run_installer(env_overrides={"FIREDAMP_BIN_DIR": readonly_bin})
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("not writable", (res.stderr + res.stdout).lower())
        finally:
            os.chmod(readonly_bin, 0o755)

    def _run_concurrent_launcher_collision_test(self, setup_launcher_fn, verify_launcher_fn):
        sync_file = os.path.join(self.test_dir, f"sync_launcher_{time.time_ns()}")
        resume_file = os.path.join(self.test_dir, f"resume_launcher_{time.time_ns()}")
        clean_repo = self._create_clean_local_repo()

        pause_code = f"""
touch "{sync_file}"
while [ ! -f "{resume_file}" ]; do
    sleep 0.02
done
"""
        launcher_marker = 'echo -e "${CYAN}[~] Publishing launcher atomically...${NC}"\n'
        script_path = self._create_mocked_installer(pause_code, pause_marker=launcher_marker)

        env = os.environ.copy()
        env["HOME"] = self.home_dir
        env["FIREDAMP_INSTALL_DIR"] = self.install_dir
        env["FIREDAMP_BIN_DIR"] = self.bin_dir

        proc = subprocess.Popen(
            ["bash", script_path],
            cwd=clean_repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        start_time = time.time()
        while not os.path.exists(sync_file):
            time.sleep(0.02)
            if time.time() - start_time > 15:
                proc.kill()
                out, err = proc.communicate()
                self.fail(f"Timeout waiting for launcher sync hook. stdout={out}, stderr={err}")

        launcher = os.path.join(self.bin_dir, "firedamp")
        self.assertFalse(os.path.lexists(launcher))

        # Concurrently create collision at LAUNCHER
        setup_launcher_fn(launcher)

        with open(resume_file, "w") as f:
            f.write("go")

        stdout, stderr = proc.communicate(timeout=15)
        self.assertNotEqual(proc.returncode, 0)
        # Verify partial installation is preserved and NOT deleted, and recovery instructions are shown
        self.assertTrue(os.path.isdir(self.install_dir), "Partial installation should NOT be deleted on launcher failure")
        self.assertIn("PARTIAL INSTALL", stderr)
        self.assertIn("Recovery options", stderr)
        self.assertNotIn("successfully installed", stdout)

        # Verify launcher collision object was preserved untouched
        verify_launcher_fn(launcher)

        # Verify launcher staging file was cleaned up
        leaked = [f for f in os.listdir(self.bin_dir) if "firedamp-launcher-staging" in f]
        self.assertEqual(leaked, [], f"Leaked launcher staging files: {leaked}")

    def test_concurrent_launcher_collision_regular_file(self):
        """Concurrent launcher collision with regular file preserves target and leaves partial install."""
        sentinel = b"CONCURRENT_LAUNCHER_FILE_DATA_123"
        digest = hashlib.sha256(sentinel).hexdigest()

        def setup(launcher):
            with open(launcher, "wb") as f:
                f.write(sentinel)

        def verify(launcher):
            self.assertFalse(os.path.islink(launcher))
            with open(launcher, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)

        self._run_concurrent_launcher_collision_test(setup, verify)

    def test_concurrent_launcher_collision_symlink(self):
        """Concurrent launcher collision with symlink never follows link and preserves target."""
        target = os.path.join(self.test_dir, "concurrent_victim.txt")
        sentinel = b"CONCURRENT_SYMLINK_VICTIM_456"
        with open(target, "wb") as f:
            f.write(sentinel)
        digest = hashlib.sha256(sentinel).hexdigest()

        def setup(launcher):
            os.symlink(target, launcher)

        def verify(launcher):
            self.assertTrue(os.path.islink(launcher))
            with open(target, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest)

        self._run_concurrent_launcher_collision_test(setup, verify)

    def test_interruption_while_creating_launcher_cleans_staging(self):
        """SIGINT during launcher staging/publication terminates safely and cleans up staging file."""
        sync_file = os.path.join(self.test_dir, f"sync_launcher_sig_{time.time_ns()}")
        clean_repo = self._create_clean_local_repo()
        pause_code = f"""
touch "{sync_file}"
while true; do
    sleep 0.02
done
"""
        launcher_marker = 'echo -e "${CYAN}[~] Publishing launcher atomically...${NC}"\n'
        script_path = self._create_mocked_installer(pause_code, pause_marker=launcher_marker)

        env = os.environ.copy()
        env["HOME"] = self.home_dir
        env["FIREDAMP_INSTALL_DIR"] = self.install_dir
        env["FIREDAMP_BIN_DIR"] = self.bin_dir

        proc = subprocess.Popen(
            ["bash", script_path],
            cwd=clean_repo,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        start_time = time.time()
        while not os.path.exists(sync_file):
            time.sleep(0.02)
            if time.time() - start_time > 15:
                proc.kill()
                proc.communicate()
                self.fail("Timeout waiting for launcher signal hook.")

        staging_files_active = [f for f in os.listdir(self.bin_dir) if "firedamp-launcher-staging" in f]
        self.assertEqual(len(staging_files_active), 1)

        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=10)
        self.assertNotEqual(proc.returncode, 0)

        staging_files_after = [f for f in os.listdir(self.bin_dir) if "firedamp-launcher-staging" in f]
        self.assertEqual(staging_files_after, [], f"Leaked launcher staging files on SIGINT: {staging_files_after}")

    def test_dirty_local_checkout_refused(self):
        """Running installer inside a dirty local git checkout is refused with clear explanation."""
        dirty_repo = self._create_clean_local_repo("dirty_repo")
        with open(os.path.join(dirty_repo, "untracked_secret.txt"), "w") as f:
            f.write("DIRTY")

        res = self._run_installer(cwd=dirty_repo)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("dirty", (res.stderr + res.stdout).lower())

    def test_remote_installer_defaults_to_pinned_v0_1_0_ref(self):
        """Remote clone defaults to v0.1.0 and honors FIREDAMP_REF override."""
        with open(INSTALL_SH, "r") as f:
            content = f.read()
        self.assertIn('DEFAULT_FIREDAMP_REF="v0.1.0"', content)
        self.assertIn('FIREDAMP_REF="${FIREDAMP_REF:-$DEFAULT_FIREDAMP_REF}"', content)
        self.assertIn('--branch "$FIREDAMP_REF"', content)


if __name__ == "__main__":
    unittest.main()
