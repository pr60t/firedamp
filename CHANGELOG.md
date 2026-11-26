# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-26

### Added
- **Core Canary Probing Engine**: Generation, injection, and zero-VRAM exact-match / entropy verification of cryptographic canary tokens (`CANARY-FRDP-...`) across multi-tenant RAG systems.
- **Audited 21-Vulnerability CVE Catalog**:
  - 4 Tier-1 automated behavioral regression probes for Open WebUI: `CVE-2026-44560` (direct vector collection bypass), `CVE-2026-45398` (raw UUID prefix bypass), `CVE-2026-28788` (cross-user batch overwrite), and `CVE-2026-54019` (Milvus multitenancy query interpolation injection).
  - 7 documented RAG vulnerabilities tracked for regression coverage (`CVE-2026-45301`, `CVE-2026-44557`, `CVE-2026-54016`, `CVE-2026-54010`, `CVE-2026-45349`, `CVE-2026-44561`, `CVE-2024-31621`).
  - 10 quarantined historical misattributions documented in `CVE_AUDIT.md`.
- **API Authorization Matrix Engine (RAG Autorize)**: Multi-persona request recording and replay (`Owner`, `Intruder`, `Ex-Member`, `Anonymous`) with Jaccard structural key-tree diffing and deterministic canary leak detection.
- **Safe Integration Lab**: Docker Compose testing harness for CVE-2026-28788 with pinned loopback bindings (`127.0.0.1:13085` and `127.0.0.1:13086`), disposable scan registries, and automated evidence sanitization.
- **Installer Safety Regression Suite**: Unit test suite (`tests/test_installer_safety.py`) verifying no-clobber behavior, symlink rejection, failure cleanup, and collision prevention in `install.sh`.

### Changed
- Refactored `install.sh` to eliminate destructive `rm -rf`, `git reset --hard`, error suppression (`|| true`), and clobbering; introduced isolated staging and trap cleanup.
- Replaced unsupported `typer[all]` extra with standard `typer` in `pyproject.toml` and `requirements.txt`.
- Reconciled root `README.md`, `wiki/Home.md`, `wiki/_Sidebar.md`, `wiki/CVE-Regression-Engine.md`, and `wiki/Version-Ladder-Benchmark.md` to accurately state benchmark simulation observations and cleanup limitations without universal guarantees.

### Fixed
- Hardened evidence collection and sanitization pipeline against credential leaks, multi-word values, YAML continuations, and key normalization edge cases (`tests/integration/openwebui_cve_2026_28788/scripts/collect_evidence.py`).
- Added robust file descriptor ownership and `fstat()` validation in evidence ingestion.
- Implemented true atomic directory replacement during evidence publication.
- Resolved PyYAML runtime dependency in `pyproject.toml` and `requirements.txt`.

### Security
- Loopback isolation enforcement (`lab_safety.py`) preventing unintended network exposure during integration testing.
- Read-only authorization matrix replay preventing accidental state corruption during permission audits.
- Pre-deletion authenticated ownership checks and disposable resource registration (`_TRUSTED_SCAN_REGISTRY`) preventing accidental deletion of pre-existing knowledge bases.

### Documentation
- Refreshed root `README.md` into a lean landing page with transparent installation instructions and explicit limitation boundaries.
- Updated `wiki/Home.md` and `wiki/_Sidebar.md` with direct navigation links to integration labs, evidence bundles, and forensic audit reports.
- Documented empirical differential validation results for CVE-2026-28788.

### Known Limitations
- Targeted post-probe cleanup for write-mutation probes uses best-effort file content restoration and vector deletion (`RESTORED_CONTENT_AND_MEMBERSHIP_VECTOR_UNVERIFIED`). The recorded reset evidence indicates `preserved_other_file_count: 0` and `verified_vector_cleanup: false`. Public top-k retrieval cannot prove exhaustive vector absence across global embedding stores.
- Live Docker validation currently covers CVE-2026-28788; other CVEs are evaluated via unit tests and simulation harnesses.
- Test user accounts created during live server audits (`alice_owner`, `bob_attacker`) persist in the target database and require manual removal if desired.
