"""
Unit tests for Firedamp Curated CVE Catalog & Registry.
"""

import unittest
from probes.cve_registry import load_cve_catalog, CVEProbe
from probes.schemas.bug_classes import BugClass, ProbeChannel


class TestCVECatalog(unittest.TestCase):
    """Test suite verifying the integrity and coverage of the curated CVE catalog."""

    def test_load_all_cves(self):
        catalog = load_cve_catalog()
        self.assertGreaterEqual(len(catalog), 20)
        for probe in catalog:
            self.assertTrue(probe.cve_id.startswith("CVE-"))
            self.assertIsInstance(probe.bug_class, BugClass)
            self.assertIsInstance(probe.probe_channel, ProbeChannel)
            self.assertTrue(len(probe.title) > 0)
            self.assertTrue(len(probe.attack_strategy) > 0)
            self.assertTrue(len(probe.behavioral_verification) > 0)

    def test_filter_by_platform(self):
        owui_cves = load_cve_catalog(platform="openwebui")
        self.assertGreaterEqual(len(owui_cves), 10)
        for c in owui_cves:
            self.assertEqual(c.platform, "openwebui")

    def test_bug_class_coverage(self):
        catalog = load_cve_catalog()
        represented_classes = {c.bug_class for c in catalog}
        # Verify all 8 bug classes have at least one curated CVE
        for bug_class in BugClass:
            self.assertIn(bug_class, represented_classes, f"Missing coverage for {bug_class}")

    def test_tier1_openwebui_ladder(self):
        # Verify the key Tier-1 Open WebUI CVEs are present
        catalog = load_cve_catalog(platform="openwebui")
        cve_ids = {c.cve_id for c in catalog}
        self.assertIn("CVE-2026-44560", cve_ids)
        self.assertIn("CVE-2026-45398", cve_ids)
        self.assertIn("CVE-2026-28788", cve_ids)
        self.assertIn("CVE-2026-54019", cve_ids)
        self.assertIn("CVE-2026-44561", cve_ids)


if __name__ == "__main__":
    unittest.main()

