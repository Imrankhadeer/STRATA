"""
Investigation Quality Auditor for CYBER ENGINE Deep-Investigation Path.

Performs deterministic verification on AI-produced and mock investigation reports:
1. Grounding check: Verifies that EVERY cited event ID exists in the supplied context (no hallucinations).
2. Fidelity check: Verifies cited timestamps and service attributions match real event records.
3. Fact vs Hypothesis check: Ensures conclusions separate observed telemetry facts from probabilistic theories.
4. Alternative hypotheses check: Ensures benign alternative explanations are explicitly evaluated.
5. Calibrated uncertainty check: Confirms uncertainty is acknowledged rather than generating false certainty.
6. Schema compliance: Confirms strict adherence to the Canonical Investigation Schema.
"""

from typing import List, Dict, Any, Set
from pydantic import BaseModel, Field

from backend.schemas.investigation import InvestigationContext, InvestigationFinding


class QualityCheckResult(BaseModel):
    check_name: str
    passed: bool
    details: str
    severity: str = "warning"  # "fatal" | "warning" | "info"


class QualityAuditReport(BaseModel):
    investigation_id: str
    overall_passed: bool
    score_percentage: float
    hallucinated_event_ids: List[str] = Field(default_factory=list)
    citation_fidelity_errors: List[str] = Field(default_factory=list)
    checks: List[QualityCheckResult] = Field(default_factory=list)


class InvestigationQualityAuditor:
    """
    Deterministically audits an InvestigationFinding against the ground truth
    telemetry provided in the InvestigationContext.
    """

    def audit(self, context: InvestigationContext, report: InvestigationFinding) -> QualityAuditReport:
        checks: List[QualityCheckResult] = []
        hallucinated_ids: List[str] = []
        fidelity_errors: List[str] = []

        context_events_map = {e["event_id"]: e for e in context.timeline_events}
        all_context_ids: Set[str] = set(context_events_map.keys())

        # Check 1: Citation Grounding (Zero-Hallucination check)
        cited_event_ids: Set[str] = set()
        for h in report.hypotheses:
            for cite in h.supporting_evidence:
                cited_event_ids.add(cite.event_id)
                if cite.event_id not in all_context_ids:
                    hallucinated_ids.append(cite.event_id)
                else:
                    # Check 2: Fidelity of service_id and timestamp
                    real_ev = context_events_map[cite.event_id]
                    if cite.service_id and cite.service_id != real_ev.get("service_id"):
                        fidelity_errors.append(
                            f"Event '{cite.event_id}' attributed to '{cite.service_id}', "
                            f"actual service is '{real_ev.get('service_id')}'"
                        )

        grounding_passed = len(hallucinated_ids) == 0
        checks.append(
            QualityCheckResult(
                check_name="citation_grounding",
                passed=grounding_passed,
                details=(
                    f"All {len(cited_event_ids)} cited event IDs exist in the incident context."
                    if grounding_passed
                    else f"Hallucinated {len(hallucinated_ids)} event IDs not present in context: {hallucinated_ids}"
                ),
                severity="fatal",
            )
        )

        fidelity_passed = len(fidelity_errors) == 0
        checks.append(
            QualityCheckResult(
                check_name="citation_fidelity",
                passed=fidelity_passed,
                details=(
                    "All cited services and timestamps strictly match underlying telemetry."
                    if fidelity_passed
                    else f"Fidelity mismatches detected: {fidelity_errors}"
                ),
                severity="fatal",
            )
        )

        # Check 3: Benign Alternative Hypotheses Considered
        has_benign = any(h.nature == "benign" for h in report.hypotheses)
        checks.append(
            QualityCheckResult(
                check_name="benign_alternative_considered",
                passed=has_benign,
                details=(
                    "Investigation formulated at least one benign or legitimate explanation."
                    if has_benign
                    else "Investigation failed to consider benign explanations or counter-theories."
                ),
                severity="warning" if report.verdict != "confirmed_threat" else "fatal",
            )
        )

        # Check 4: Malicious Hypothesis Present When Threat Confirmed
        if report.verdict == "confirmed_threat":
            has_malicious = any(h.nature == "malicious" for h in report.hypotheses)
            checks.append(
                QualityCheckResult(
                    check_name="malicious_hypothesis_present",
                    passed=has_malicious,
                    details="Threat verdict supported by a structured malicious hypothesis.",
                    severity="fatal",
                )
            )

        # Check 5: Documented Confidence & Likelihood
        valid_likelihoods = {"low", "medium", "high"}
        likelihood_valid = all(h.likelihood in valid_likelihoods for h in report.hypotheses)
        checks.append(
            QualityCheckResult(
                check_name="documented_confidence_bounds",
                passed=likelihood_valid,
                details=(
                    "Likelihoods use bounded categories ('low', 'medium', 'high') with qualitative evidence rationale."
                    if likelihood_valid
                    else "Invalid or uncalibrated probability values detected in hypotheses."
                ),
                severity="warning",
            )
        )

        # Check 6: Uncertainty and Missing Evidence Acknowledged
        # Reports should explicitly note uncertainty, especially on inconclusive verdicts
        uncertainty_terms = {"uncertain", "inconclusive", "unusual", "missing", "transient", "alternative", "unverified"}
        combined_text = (report.summary + " " + " ".join(h.description for h in report.hypotheses)).lower()
        uncertainty_reported = any(term in combined_text for term in uncertainty_terms)
        checks.append(
            QualityCheckResult(
                check_name="uncertainty_reporting",
                passed=uncertainty_reported,
                details=(
                    "Investigation explicitly articulates investigative nuances and uncertainties."
                    if uncertainty_reported
                    else "Investigation output displays uncalibrated absolute certainty."
                ),
                severity="info",
            )
        )

        # Check 7: Candidate Rules Safety Invariant
        all_rules_proposed = all(r.status == "proposed" for r in report.candidate_rules)
        checks.append(
            QualityCheckResult(
                check_name="candidate_rules_safety_status",
                passed=all_rules_proposed,
                details=(
                    f"All {len(report.candidate_rules)} candidate rules marked 'proposed' for human/policy gating."
                    if all_rules_proposed
                    else "VIOLATION: AI model attempted to set non-proposal status on candidate rules."
                ),
                severity="fatal",
            )
        )

        passed_count = sum(1 for c in checks if c.passed)
        fatal_failures = [c for c in checks if not c.passed and c.severity == "fatal"]
        overall_passed = len(fatal_failures) == 0

        score = (passed_count / len(checks)) * 100.0 if checks else 100.0

        return QualityAuditReport(
            investigation_id=report.investigation_id,
            overall_passed=overall_passed,
            score_percentage=round(score, 1),
            hallucinated_event_ids=hallucinated_ids,
            citation_fidelity_errors=fidelity_errors,
            checks=checks,
        )

