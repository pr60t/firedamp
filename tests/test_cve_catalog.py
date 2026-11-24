"""
Unit and Schema Integrity Tests for Firedamp Curated CVE Catalog & Registry.
Verifies Phase 1-7 forensic audit requirements:
- Zero unverified or fabricated CVEs
- Accurate status tracking (implemented, documented, rejected)
- Probe path resolution
- Uniqueness and URL validity
"""

import unittest
from pathlib import Path

from probes.cve_registry import (
    CVEProbe,
    CVEStatus,
    load_cve_catalog,
    validate_cve_catalog,
)
from probes.schemas.bug_classes import BugClass, ProbeChannel


class TestCVECatalog(unittest.TestCase):
    """Test suite verifying the forensic accuracy and integrity of the curated CVE catalog."""

    def test_automated_catalog_schema_validation(self):
        """Phase 7: Run automated schema validation over the entire 21-CVE catalog."""
        errors = validate_cve_catalog()
        self.assertEqual(
            errors,
            [],
            f"CVE catalog schema validation failed with errors:\n" + "\n".join(errors),
        )

    def test_load_all_21_audited_entries(self):
        """Verify that all 21 audited CVE entries load with complete metadata."""
        catalog = load_cve_catalog(include_rejected=True)
        self.assertEqual(len(catalog), 21, "Total audited catalog must contain exactly 21 entries.")
        seen_ids = set()
        for probe in catalog:
            self.assertTrue(probe.cve_id.startswith("CVE-"))
            self.assertNotIn(probe.cve_id, seen_ids, f"Duplicate CVE ID: {probe.cve_id}")
            seen_ids.add(probe.cve_id)
            self.assertTrue(len(probe.title) > 0)
            self.assertTrue(len(probe.vendor) > 0)
            self.assertTrue(len(probe.product) > 0)
            self.assertTrue(len(probe.description) > 0)
            self.assertTrue(len(probe.cwe_id) > 0)
            self.assertGreater(len(probe.official_references), 0)

    def test_filter_by_platform_openwebui(self):
        """Verify that Open WebUI catalog contains the 10 verified CVEs."""
        owui_cves = load_cve_catalog(platform="openwebui")
        self.assertEqual(len(owui_cves), 10, "Expected exactly 10 verified Open WebUI CVEs.")
        for c in owui_cves:
            self.assertEqual(c.platform, "openwebui")
            self.assertEqual(c.vendor, "Open WebUI")
            self.assertTrue(c.is_active)

    def test_tier1_openwebui_ladder_probes(self):
        """Verify the 4 Tier-1 Open WebUI regression probes are implemented and resolve to files."""
        implemented_cves = load_cve_catalog(status=CVEStatus.IMPLEMENTED.value)
        self.assertEqual(len(implemented_cves), 4, "Expected exactly 4 implemented probes.")

        implemented_ids = {c.cve_id for c in implemented_cves}
        expected_tier1 = {
            "CVE-2026-44560",
            "CVE-2026-45398",
            "CVE-2026-28788",
            "CVE-2026-54019",
        }
        self.assertEqual(implemented_ids, expected_tier1)

        repo_root = Path(__file__).parent.parent
        for probe in implemented_cves:
            self.assertTrue(probe.probe_implemented)
            self.assertIsNotNone(probe.probe_path)
            probe_file = repo_root / probe.probe_path
            self.assertTrue(
                probe_file.is_file(),
                f"Probe path '{probe.probe_path}' does not resolve to an existing file.",
            )

    def test_rejected_misattributions_quarantine(self):
        """Phase 3 & 5: Verify that the 10 misattributed CVEs are classified as rejected with reasons."""
        rejected_cves = load_cve_catalog(status=CVEStatus.REJECTED.value)
        self.assertEqual(len(rejected_cves), 10, "Expected exactly 10 rejected misattributions.")

        rejected_ids = {c.cve_id for c in rejected_cves}
        expected_rejected = {
            "CVE-2024-52306",  # Backpack FileManager
            "CVE-2024-52307",  # authentik
            "CVE-2024-41133",  # HPE Aruba SD-WAN
            "CVE-2024-43407",  # CKEditor 4
            "CVE-2024-52308",  # GitHub CLI
            "CVE-2024-45388",  # Hoverfly
            "CVE-2024-45389",  # Pagefind
            "CVE-2024-42475",  # Nim OAuth
            "CVE-2024-45391",  # TinaCMS
            "CVE-2024-34359",  # llama-cpp-python
        }
        self.assertEqual(rejected_ids, expected_rejected)

        for c in rejected_cves:
            self.assertFalse(c.is_active)
            self.assertFalse(c.probe_implemented)
            self.assertIsNone(c.probe_path)
            self.assertIsNotNone(c.rejection_reason)
            self.assertGreater(len(c.rejection_reason), 20)

    def test_flowise_documented_cve(self):
        """Phase 3 & 5: Verify Flowise CVE-2024-31621 is documented with corrected RCE/auth metadata."""
        flowise_cves = load_cve_catalog(platform="flowise")
        self.assertEqual(len(flowise_cves), 1)
        f_cve = flowise_cves[0]
        self.assertEqual(f_cve.cve_id, "CVE-2024-31621")
        self.assertEqual(f_cve.probe_status, CVEStatus.DOCUMENTED.value)
        self.assertEqual(f_cve.vendor, "FlowiseAI")
        self.assertIn("1.8.1", f_cve.fixed_versions)
        self.assertFalse(f_cve.probe_implemented)

    def test_active_catalog_filtering(self):
        """Verify that include_rejected=False filters out all rejected records."""
        active_cves = load_cve_catalog(include_rejected=False)
        self.assertEqual(len(active_cves), 11, "Active catalog must contain 11 verified records.")
        for c in active_cves:
            self.assertTrue(c.is_active)
            self.assertNotEqual(c.probe_status, CVEStatus.REJECTED.value)


if __name__ == "__main__":
    unittest.main()
