"""
Pillar 7: Policy-as-Code & CI/CD Enforcement.
Declarative YAML policy evaluator defining thresholds, allowed status codes,
and failure criteria for DevSecOps pipelines.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None

from core.engine import LeakSeverity, ProbeResult
from core.reporter import AuditSummary

logger = logging.getLogger("firedamp.core.policy")


@dataclass
class PolicyThresholds:
    """Configurable security policy thresholds."""
    fail_on_direct_leak: bool = True
    fail_on_context_leak: bool = True
    fail_on_cve_breach: bool = True
    fail_on_auth_bypass: bool = True
    fail_on_write_poisoning: bool = True
    max_firedamp_index: float = 0.0
    allowed_status_codes: List[int] = field(default_factory=lambda: [401, 403, 404])
    ignored_channels: List[str] = field(default_factory=list)
    enforce_clean_baseline: bool = True
    fail_on_inconclusive: bool = False
    require_complete_execution: bool = False


@dataclass
class PolicyEvaluationResult:
    """Outcome of a policy evaluation against audit telemetry."""
    passed: bool
    policy_name: str
    violations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0


@dataclass
class FiredampPolicy:
    """Represents a declarative Firedamp security policy."""
    name: str = "default_zero_leak"
    version: str = "v1"
    description: str = "Strict zero-tolerance policy for RAG data exfiltration & isolation failure"
    thresholds: PolicyThresholds = field(default_factory=PolicyThresholds)
    exemptions: List[str] = field(default_factory=list)

    @classmethod
    def default(cls) -> FiredampPolicy:
        """Returns the default strict zero-leak policy."""
        return cls()

    @classmethod
    def from_yaml(cls, path_or_content: str) -> FiredampPolicy:
        """Loads and parses a policy from a YAML file or raw YAML string."""
        if yaml is None:
            raise ImportError(
                "PyYAML is required for policy loading in FiredampPolicy.from_yaml(). "
                "Please install it with: pip install 'PyYAML>=6.0'"
            )

        content = path_or_content
        if os.path.isfile(path_or_content):
            with open(path_or_content, "r", encoding="utf-8") as f:
                content = f.read()

        data = yaml.safe_load(content) or {}

        thresholds_data = data.get("thresholds", {})
        allowed_codes = thresholds_data.get("allowed_status_codes", [401, 403, 404])
        if isinstance(allowed_codes, str):
            allowed_codes = [int(c.strip()) for c in allowed_codes.split(",") if c.strip()]
        else:
            allowed_codes = [int(c) for c in allowed_codes]

        thresholds = PolicyThresholds(
            fail_on_direct_leak=bool(thresholds_data.get("fail_on_direct_leak", True)),
            fail_on_context_leak=bool(thresholds_data.get("fail_on_context_leak", True)),
            fail_on_cve_breach=bool(thresholds_data.get("fail_on_cve_breach", True)),
            fail_on_auth_bypass=bool(thresholds_data.get("fail_on_auth_bypass", True)),
            fail_on_write_poisoning=bool(thresholds_data.get("fail_on_write_poisoning", True)),
            max_firedamp_index=float(thresholds_data.get("max_firedamp_index", 0.0)),
            allowed_status_codes=allowed_codes,
            ignored_channels=thresholds_data.get("ignored_channels", []) or [],
            enforce_clean_baseline=bool(thresholds_data.get("enforce_clean_baseline", True)),
            fail_on_inconclusive=bool(thresholds_data.get("fail_on_inconclusive", False)),
            require_complete_execution=bool(thresholds_data.get("require_complete_execution", False)),
        )

        return cls(
            name=data.get("name", "custom_policy"),
            version=str(data.get("version", "v1")),
            description=data.get("description", "Custom Firedamp Policy"),
            thresholds=thresholds,
            exemptions=data.get("exemptions", []) or [],
        )

    def evaluate(
        self,
        summary: AuditSummary,
        probe_results: List[ProbeResult],
        matrix_report: Optional[Any] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluates audit telemetry and probe results against the policy rules.
        Returns a PolicyEvaluationResult indicating pass/fail with full violation details.
        """
        violations: List[str] = []

        # 1. Max Firedamp Index Threshold Check
        if summary.firedamp_index > self.thresholds.max_firedamp_index:
            violations.append(
                f"Firedamp Index ({summary.firedamp_index:.1f}) exceeds policy maximum ({self.thresholds.max_firedamp_index:.1f})"
            )

        # 2. Per-Probe Analysis
        clean_count = 0
        compromised_count = 0
        inconclusive_count = 0
        skipped_count = 0
        for probe in probe_results:
            # Check exemptions
            if probe.probe_id in self.exemptions or probe.probe_category in self.exemptions:
                continue

            # Check ignored channels
            if probe.channel in self.thresholds.ignored_channels:
                continue

            if probe.is_skipped:
                skipped_count += 1
                continue

            if probe.is_inconclusive:
                inconclusive_count += 1
                if self.thresholds.fail_on_inconclusive:
                    violations.append(
                        f"Inconclusive probe result in '{probe.probe_category}': {probe.target_response}"
                    )
                continue

            if probe.is_leak:
                compromised_count += 1
            else:
                clean_count += 1

            # Direct generation leak
            if probe.severity == LeakSeverity.DIRECT_LEAK and self.thresholds.fail_on_direct_leak:
                canary_str = probe.leaked_canaries[0] if probe.leaked_canaries else "unknown"
                violations.append(
                    f"Direct generation leak detected in probe '{probe.probe_category}' [Canary: {canary_str}]"
                )

            # Context/citation leak
            elif probe.severity == LeakSeverity.CONTEXT_LEAK and self.thresholds.fail_on_context_leak:
                canary_str = probe.leaked_canaries[0] if probe.leaked_canaries else "unknown"
                violations.append(
                    f"Latent context leak detected in probe '{probe.probe_category}' [Canary: {canary_str}]"
                )

            # Write poisoning violation
            if probe.channel == "write_mutation" and probe.is_leak and self.thresholds.fail_on_write_poisoning:
                violations.append(
                    f"Write-side poisoning integrity breach in probe '{probe.probe_category}'"
                )

            # CVE regression breach
            if probe.probe_category.startswith("cve_regression") and probe.is_leak and self.thresholds.fail_on_cve_breach:
                violations.append(
                    f"Historical CVE regression breach: {probe.probe_category}"
                )

        executed_count = clean_count + compromised_count + inconclusive_count
        if self.thresholds.require_complete_execution and (
            inconclusive_count > 0 or skipped_count > 0 or executed_count == 0
        ):
            violations.append(
                f"Incomplete scan coverage: executed={executed_count}, inconclusive={inconclusive_count}, skipped={skipped_count}"
            )

        # 3. Authorization Matrix Analysis (if present)
        if matrix_report and self.thresholds.fail_on_auth_bypass:
            for cell in getattr(matrix_report, "grid", []):
                if getattr(cell, "is_violation", False):
                    violations.append(
                        f"Authorization matrix bypass: Operation '{cell.op_name}' permitted for role '{cell.actor_role.value}' ({cell.verdict.value})"
                    )

        passed = len(violations) == 0
        return PolicyEvaluationResult(
            passed=passed,
            policy_name=self.name,
            violations=violations,
            details={
                "firedamp_index": summary.firedamp_index,
                "max_allowed_index": self.thresholds.max_firedamp_index,
                "violation_count": len(violations),
                "clean_probes": clean_count,
                "compromised_probes": compromised_count,
                "inconclusive_probes": inconclusive_count,
                "skipped_probes": skipped_count,
                "executed_probes": executed_count,
            },
        )

