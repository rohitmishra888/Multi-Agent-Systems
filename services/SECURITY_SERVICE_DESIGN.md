# Security Service
Phase 2 orchestrator running all 6 OWASP test modules in sequence:
auth_tester -> bola_tester -> injection_tester -> data_exposure_tester
-> mass_assignment_tester -> rate_limit_tester
Aggregates VulnerabilityFinding results into SecurityReport.
