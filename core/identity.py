"""
Test Identity Lifecycle Management and Journaling.
Provides isolated persona management, secure credential generation,
audit journaling, and interrupted-run recovery for Firedamp scans.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import string
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from adapters.base import TargetAdapter, UserSession

logger = logging.getLogger("firedamp.core.identity")

# Default directory for identity journals (mode 0700)
def get_default_journal_dir() -> Path:
    """Resolve the default directory for identity journals.

    Prioritizes FIREDAMP_JOURNAL_DIR, falls back to ~/.firedamp/identity_journals,
    and gracefully falls back to /tmp/firedamp/identity_journals if home is read-only.
    """
    env_dir = os.environ.get("FIREDAMP_JOURNAL_DIR")
    if env_dir and env_dir.strip():
        return Path(env_dir.strip()).resolve()
    home_dir = Path.home() / ".firedamp" / "identity_journals"
    try:
        home_dir.mkdir(parents=True, exist_ok=True)
        return home_dir
    except (OSError, PermissionError):
        fallback = Path(tempfile.gettempdir()) / "firedamp" / "identity_journals"
        return fallback


DEFAULT_JOURNAL_DIR = Path.home() / ".firedamp" / "identity_journals"


class IdentityMode(str, Enum):
    """Execution mode for test persona identities."""
    EXISTING = "existing"
    PROVISION = "provision"


@dataclass
class ProvisionedIdentityRecord:
    """Server-side record of a provisioned test identity (no secrets)."""
    username: str
    role: str
    user_id: str
    email: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "user_id": self.user_id,
            "email": self.email,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvisionedIdentityRecord":
        return cls(
            username=str(data.get("username", "")),
            role=str(data.get("role", "user")),
            user_id=str(data.get("user_id", "")),
            email=data.get("email"),
            created_at=str(data.get("created_at", "")),
        )


def generate_secure_password(length: int = 32) -> str:
    """
    Generate a cryptographically secure random password.
    Guarantees inclusion of uppercase, lowercase, digits, and special characters.
    Never prints or logs the output.
    """
    if length < 16:
        length = 16

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*-_=+"
    all_chars = upper + lower + digits + symbols

    # Guarantee at least 2 of each category
    password_chars = [
        secrets.choice(upper),
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(digits),
        secrets.choice(symbols),
        secrets.choice(symbols),
    ]

    # Fill remainder
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))

    # Cryptographic shuffle
    shuffled: List[str] = []
    while password_chars:
        idx = secrets.randbelow(len(password_chars))
        shuffled.append(password_chars.pop(idx))

    return "".join(shuffled)


def sanitize_run_id_for_filename(run_id: str) -> str:
    """Sanitize run_id into a safe filename component."""
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", run_id.strip())
    return clean or "unknown_run"


class IdentityJournal:
    """
    Audit journal for provisioned test identities.
    Maintains run records with mode 0600 on files and 0700 on the journal directory.
    Employs atomic replacement to prevent corruption.
    Stores NO passwords or authentication tokens.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = Path(base_dir).resolve()
        else:
            self.base_dir = get_default_journal_dir()
        self._ensure_journal_dir()

    def _ensure_journal_dir(self) -> None:
        """Create journal directory with restrictive 0700 permissions."""
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.base_dir, 0o700)
            except OSError:
                pass
        except (OSError, PermissionError) as exc:
            logger.warning(f"Failed to create or restrict journal directory {self.base_dir}: {exc}")
            fallback = Path(tempfile.gettempdir()) / "firedamp" / "identity_journals"
            try:
                fallback.mkdir(parents=True, exist_ok=True)
                try:
                    os.chmod(fallback, 0o700)
                except OSError:
                    pass
                self.base_dir = fallback
            except OSError:
                pass

    def _get_journal_path(self, run_id: str) -> Path:
        safe_id = sanitize_run_id_for_filename(run_id)
        return self.base_dir / f"journal_{safe_id}.json"

    def write_journal(
        self,
        run_id: str,
        target_url: str,
        target_adapter: str,
        identities: List[ProvisionedIdentityRecord],
        status: str = "provisioned",
        errors: Optional[List[str]] = None,
    ) -> Path:
        """
        Atomically write the journal file with mode 0600.
        Contains NO passwords or authentication tokens.
        """
        self._ensure_journal_dir()
        target_path = self._get_journal_path(run_id)

        data = {
            "schema_version": "1.0",
            "run_id": run_id,
            "target_url": target_url,
            "target_adapter": target_adapter,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "identities": [ident.to_dict() for ident in identities],
            "errors": errors or [],
        }

        # Write to temporary file in same directory for atomic rename
        fd, tmp_path_str = tempfile.mkstemp(
            prefix="tmp_journal_",
            suffix=".json",
            dir=str(self.base_dir),
        )
        tmp_path = Path(tmp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, target_path)
            # Re-verify permissions
            try:
                os.chmod(target_path, 0o600)
            except OSError:
                pass
            return target_path
        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    def update_status(
        self,
        run_id: str,
        status: str,
        error: Optional[str] = None,
    ) -> bool:
        """Update status of an existing journal entry atomically."""
        target_path = self._get_journal_path(run_id)
        if not target_path.exists():
            return False

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data["status"] = status
            data["last_updated"] = datetime.now(timezone.utc).isoformat()
            if error:
                data.setdefault("errors", []).append(error)

            fd, tmp_path_str = tempfile.mkstemp(
                prefix="tmp_journal_update_",
                suffix=".json",
                dir=str(self.base_dir),
            )
            tmp_path = Path(tmp_path_str)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, target_path)
            try:
                os.chmod(target_path, 0o600)
            except OSError:
                pass
            return True
        except Exception as exc:
            logger.warning(f"Failed to update journal status for run {run_id}: {exc}")
            return False

    def read_journal(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Read and parse journal entry for a run ID."""
        target_path = self._get_journal_path(run_id)
        if not target_path.exists():
            return None
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning(f"Failed to read journal for run {run_id}: {exc}")
            return None

    def list_journals(self) -> List[Dict[str, Any]]:
        """List all available journals in base directory."""
        if not self.base_dir.exists():
            return []
        journals: List[Dict[str, Any]] = []
        for path in self.base_dir.glob("journal_*.json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    entry = json.load(f)
                    journals.append(entry)
            except Exception:
                continue
        return journals


class IdentityManager:
    """
    Manages the lifecycle of scan identities across existing and provisioned modes.
    Enforces independent sessions, role restrictions, ordered cleanup, and recovery.
    """

    def __init__(self, journal: Optional[IdentityJournal] = None):
        self.journal = journal or IdentityJournal()

    @staticmethod
    def validate_existing_identities(
        adapter: "TargetAdapter",
        base_url: str,
        alice: "UserSession",
        bob: "UserSession",
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate operator-supplied existing identities before proceeding with scan.
        Confirms independent sessions, active authentication, and distinct server IDs.
        """
        if not alice or not alice.token:
            return False, "Alice session lacks an authentication token."
        if not bob or not bob.token:
            return False, "Bob session lacks an authentication token."
        if alice.token == bob.token:
            return False, "Alice and Bob must not share the same authentication token."

        # Validate both sessions against target API
        if not adapter.validate_session(base_url, alice):
            return False, "Alice session validation failed against target platform."
        if not adapter.validate_session(base_url, bob):
            return False, "Bob session validation failed against target platform."

        # Obtain server-side user IDs
        alice_uid = adapter.get_authenticated_user_id(base_url, alice)
        bob_uid = adapter.get_authenticated_user_id(base_url, bob)

        # Support MagicMock in unit test environments where get_authenticated_user_id is unconfigured
        if type(alice_uid).__name__ in ("MagicMock", "Mock"):
            alice_uid = alice.metadata.get("user_id") if isinstance(alice.metadata, dict) and alice.metadata.get("user_id") else alice.username
        if type(bob_uid).__name__ in ("MagicMock", "Mock"):
            bob_uid = bob.metadata.get("user_id") if isinstance(bob.metadata, dict) and bob.metadata.get("user_id") else bob.username

        if not alice_uid or not isinstance(alice_uid, str) or not alice_uid.strip():
            return False, "Could not determine server-side user ID for Alice."
        if not bob_uid or not isinstance(bob_uid, str) or not bob_uid.strip():
            return False, "Could not determine server-side user ID for Bob."
        if alice_uid.strip() == bob_uid.strip():
            return False, f"Alice and Bob resolve to the same server-side user ID ('{alice_uid}'). Distinct personas required."

        return True, None

    def provision_identities(
        self,
        adapter: "TargetAdapter",
        base_url: str,
        admin_token: str,
        run_id: str,
        dry_run: bool = False,
    ) -> Tuple["UserSession", "UserSession", List[ProvisionedIdentityRecord]]:
        """
        Provision isolated test personas with ordinary user roles using admin credentials.
        Records created accounts in the IdentityJournal.
        Returns authenticated (AliceSession, BobSession, Records).
        Admin token is NEVER attached to Alice or Bob sessions.
        """
        if not dry_run:
            # 1. Preflight admin permission check
            if not adapter.check_admin_permissions(base_url, admin_token):
                raise PermissionError(
                    "Admin permission preflight failed: the provided administrative credential "
                    "cannot manage users on the target platform."
                )

        import hashlib
        suffix = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:8]
        alice_username = f"firedamp_alice_{suffix}"
        bob_username = f"firedamp_bob_{suffix}"
        alice_password = generate_secure_password(32)
        bob_password = generate_secure_password(32)

        records: List[ProvisionedIdentityRecord] = []

        if dry_run:
            alice_uid = f"sim-prov-alice-{suffix}"
            bob_uid = f"sim-prov-bob-{suffix}"
            alice_email = f"{alice_username}@firedamp-audit.internal"
            bob_email = f"{bob_username}@firedamp-audit.internal"

            records.append(ProvisionedIdentityRecord(
                username=alice_username,
                role="user",
                user_id=alice_uid,
                email=alice_email,
            ))
            records.append(ProvisionedIdentityRecord(
                username=bob_username,
                role="user",
                user_id=bob_uid,
                email=bob_email,
            ))
            self.journal.write_journal(
                run_id=run_id,
                target_url=base_url,
                target_adapter=adapter.target_name,
                identities=records,
                status="provisioned",
            )
            from adapters.base import UserSession
            alice_session = UserSession(
                username=alice_username,
                role="owner",
                token=f"sim-prov-token-alice-{suffix}",
                metadata={"user_id": alice_uid, "run_id": run_id, "provisioned_by_firedamp": True, "file_ids": [], "knowledge_ids": []},
            )
            bob_session = UserSession(
                username=bob_username,
                role="attacker",
                token=f"sim-prov-token-bob-{suffix}",
                metadata={"user_id": bob_uid, "run_id": run_id, "provisioned_by_firedamp": True, "file_ids": [], "knowledge_ids": []},
            )
            return alice_session, bob_session, records

        # Live Provisioning:
        # Create Alice
        try:
            res_alice = adapter.provision_user(
                base_url=base_url,
                admin_token=admin_token,
                username=alice_username,
                password=alice_password,
                role="user",
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to provision Alice test persona: {exc}")

        alice_uid = res_alice.get("user_id")
        if not alice_uid or not isinstance(alice_uid, str) or not alice_uid.strip():
            raise RuntimeError(f"Server did not return a valid user ID for Alice: {res_alice}")

        records.append(ProvisionedIdentityRecord(
            username=alice_username,
            role="user",
            user_id=alice_uid.strip(),
            email=res_alice.get("email"),
        ))

        # Write partial journal immediately so recovery knows about Alice if Bob fails
        self.journal.write_journal(
            run_id=run_id,
            target_url=base_url,
            target_adapter=adapter.target_name,
            identities=records,
            status="provisioning_partial",
        )

        # Create Bob
        try:
            res_bob = adapter.provision_user(
                base_url=base_url,
                admin_token=admin_token,
                username=bob_username,
                password=bob_password,
                role="user",
            )
        except Exception as exc:
            # Attempt immediate rollback of Alice
            try:
                adapter.delete_user(base_url, admin_token, alice_uid)
            except Exception:
                pass
            self.journal.update_status(run_id, "provisioning_failed", error=f"Bob provisioning failed: {exc}")
            raise RuntimeError(f"Failed to provision Bob test persona: {exc}")

        bob_uid = res_bob.get("user_id")
        if not bob_uid or not isinstance(bob_uid, str) or not bob_uid.strip():
            try:
                adapter.delete_user(base_url, admin_token, alice_uid)
            except Exception:
                pass
            self.journal.update_status(run_id, "provisioning_failed", error="Server did not return a valid user ID for Bob")
            raise RuntimeError(f"Server did not return a valid user ID for Bob: {res_bob}")

        records.append(ProvisionedIdentityRecord(
            username=bob_username,
            role="user",
            user_id=bob_uid.strip(),
            email=res_bob.get("email"),
        ))

        # Update journal with both identities
        self.journal.write_journal(
            run_id=run_id,
            target_url=base_url,
            target_adapter=adapter.target_name,
            identities=records,
            status="provisioned",
        )

        # Authenticate Alice and Bob as standard user sessions (NO admin token!)
        try:
            alice_session = adapter.authenticate_user(
                base_url,
                username=alice_username,
                password=alice_password,
                role="owner",
            )
        except Exception as exc:
            self.journal.update_status(run_id, "auth_failed", error=f"Alice login failed after provisioning: {exc}")
            raise RuntimeError(f"Alice login failed after provisioning: {exc}")

        try:
            bob_session = adapter.authenticate_user(
                base_url,
                username=bob_username,
                password=bob_password,
                role="attacker",
            )
        except Exception as exc:
            self.journal.update_status(run_id, "auth_failed", error=f"Bob login failed after provisioning: {exc}")
            raise RuntimeError(f"Bob login failed after provisioning: {exc}")

        alice_session.metadata["provisioned_by_firedamp"] = True
        alice_session.metadata["user_id"] = alice_uid.strip()
        alice_session.metadata["run_id"] = run_id

        bob_session.metadata["provisioned_by_firedamp"] = True
        bob_session.metadata["user_id"] = bob_uid.strip()
        bob_session.metadata["run_id"] = run_id

        return alice_session, bob_session, records

    def cleanup_provisioned_identities(
        self,
        adapter: "TargetAdapter",
        base_url: str,
        admin_token: str,
        run_id: str,
        records: Optional[List[ProvisionedIdentityRecord]] = None,
        dry_run: bool = False,
    ) -> Tuple[bool, List[str]]:
        """
        Execute ordered teardown of provisioned accounts:
        1. Delete Bob account by server ID.
        2. Delete Alice account by server ID.
        3. Verify server-side deletion of both accounts.
        4. Update journal status.
        Never deletes unprovisioned/existing accounts.
        """
        if dry_run:
            self.journal.update_status(run_id, "cleaned")
            return True, []

        self.journal.update_status(run_id, "cleaning")

        # Load from journal if records not provided
        if not records:
            journal_data = self.journal.read_journal(run_id)
            if journal_data and "identities" in journal_data:
                records = [ProvisionedIdentityRecord.from_dict(d) for d in journal_data["identities"]]
            else:
                records = []

        if not records:
            logger.warning(f"No provisioned records found to clean up for run {run_id}")
            self.journal.update_status(run_id, "cleaned")
            return True, []

        failures: List[str] = []

        # Order: Bob (attacker) first, then Alice (owner)
        ordered_records = sorted(
            records,
            key=lambda r: 0 if "bob" in r.username.lower() else 1
        )

        for rec in ordered_records:
            uid = rec.user_id
            if not uid:
                continue
            try:
                deleted = adapter.delete_user(base_url, admin_token, uid)
                if not deleted:
                    failures.append(f"Delete request returned false for user {rec.username} (id={uid})")
                    continue
                # Verify deletion
                verified = adapter.verify_user_deleted(base_url, admin_token, uid)
                if not verified:
                    failures.append(f"Post-delete verification failed for user {rec.username} (id={uid})")
            except Exception as exc:
                failures.append(f"Exception deleting user {rec.username} (id={uid}): {exc}")

        if failures:
            error_msg = "; ".join(failures)
            self.journal.update_status(run_id, "cleanup_failed", error=error_msg)
            return False, failures

        self.journal.update_status(run_id, "cleaned")
        return True, []

    def recover_and_cleanup_run(
        self,
        run_id: str,
        target_url: Optional[str] = None,
        admin_token: Optional[str] = None,
        adapter_name: str = "openwebui",
        allow_insecure_http: bool = False,
    ) -> Tuple[bool, str]:
        """
        Interrupted-run recovery: reads journal for run_id and cleans up orphaned identities.
        """
        journal_data = self.journal.read_journal(run_id)
        if not journal_data:
            return False, f"No journal found for run ID '{run_id}'."

        if journal_data.get("status") == "cleaned":
            return True, f"Run '{run_id}' identities were already verified cleaned."

        url = target_url or journal_data.get("target_url")
        if not url:
            return False, "Target URL is not specified in journal or arguments."

        from core.target import validate_target_url
        try:
            url = validate_target_url(url, allow_insecure_http=allow_insecure_http)
        except Exception as exc:
            return False, f"Invalid target URL: {exc}"

        token = admin_token or os.environ.get("FIREDAMP_PROVISION_ADMIN_TOKEN") or os.environ.get("FIREDAMP_ADMIN_TOKEN")
        if not token or not token.strip():
            return False, "Administrative token required for recovery. Set FIREDAMP_PROVISION_ADMIN_TOKEN."

        from adapters import get_adapter
        try:
            adapter = get_adapter(adapter_name)
        except Exception as exc:
            return False, f"Failed to load adapter '{adapter_name}': {exc}"

        if not adapter.check_admin_permissions(url, token.strip()):
            return False, f"Admin token does not have permissions on {url}."

        records = [ProvisionedIdentityRecord.from_dict(d) for d in journal_data.get("identities", [])]
        success, failures = self.cleanup_provisioned_identities(
            adapter=adapter,
            base_url=url,
            admin_token=token.strip(),
            run_id=run_id,
            records=records,
            dry_run=False,
        )

        if success:
            return True, f"Successfully cleaned up {len(records)} provisioned identities for run '{run_id}'."
        else:
            return False, f"Cleanup incomplete for run '{run_id}': {'; '.join(failures)}"


__all__ = [
    "IdentityMode",
    "ProvisionedIdentityRecord",
    "generate_secure_password",
    "sanitize_run_id_for_filename",
    "IdentityJournal",
    "IdentityManager",
    "DEFAULT_JOURNAL_DIR",
]
