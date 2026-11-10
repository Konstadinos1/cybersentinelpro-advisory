# Control mapping

How each control maps to the frameworks this project targets. Rule IDs appear in
findings, audit events and red-team reports.

## OWASP Top 10 for LLM Applications 2026

| ID | Risk | Controls | Rule IDs |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | Tool metadata and result scanning, hidden-character detection, RAG ingestion and retrieval scanning, spotlighting of retrieved text | AEGIS-TP-001 to 007, 020 to 022 |
| LLM02 | Sensitive Information Disclosure | DLP redaction of secrets and PII, sensitive-path detection in tool arguments, image exfiltration stripping | AEGIS-DLP-*, AEGIS-TP-010, AEGIS-SINK-MD-001 |
| LLM03 | Excessive Agency | Default-deny RBAC on the human identity, impact classification, human approval gate | policy decisions, approval gate |
| LLM04 | Supply Chain | sha256 pinning of tool definitions, HMAC-protected lock file, package allowlist | AEGIS-FW-010, 011, AEGIS-SINK-PKG-* |
| LLM05 | Data and Model Poisoning | Trusted-source allowlist, ingestion scan, chunk integrity digests | AEGIS-RAG-002, 011 |
| LLM06 | Unbounded Consumption | Step, recursion, token and cost ceilings; loop detection | circuit breaker trip reasons |
| LLM07 | Misinformation | Package recommendations verified against a trusted registry (slopsquatting) | AEGIS-SINK-PKG-001, 002 |
| LLM08 | Hidden Context Exposure | Canary redaction, reasoning-trace removal | AEGIS-DLP-CANARY, AEGIS-DLP-REASONING |
| LLM09 | Vector and Embedding Weaknesses | Per-tenant partitions, role-scoped chunks, retrieval-time tenant assertion, honeypot records | AEGIS-RAG-010, 012 |
| LLM10 | Improper Output Handling | Shell, SQL and Markdown sink validators | AEGIS-SINK-SH-*, AEGIS-SINK-SQL-*, AEGIS-SINK-MD-001 |

## OWASP Top 10 for Agentic Applications

| ID | Risk | Controls |
| --- | --- | --- |
| ASI01 | Agent Goal Hijack | Tool-result and document scanning; approval gate limits what a hijacked agent can do |
| ASI02 | Tool Misuse and Exploitation | Closed-schema argument validation, covert-parameter detection, cross-tool shadowing rule |
| ASI03 | Identity and Privilege Abuse | Decisions bound to the verified human; separation of duties on approvals |
| ASI04 | Agentic Supply Chain Vulnerabilities | Tool pinning and rug-pull detection |
| ASI05 | Unexpected Code Execution | Shell command validator; argv returned for `shell=False` |
| ASI06 | Memory and Context Poisoning | RAG ingestion controls, integrity digests, retrieval re-scan |
| ASI07 | Insecure Inter-Agent Communication | Not addressed. Out of scope for this release |
| ASI08 | Cascading Failures | Circuit breakers; a tripped run stays stopped |
| ASI09 | Human-Agent Trust Exploitation | Approvals bound to the exact call digest, single use, short expiry |
| ASI10 | Rogue Agents | Partially: budgets and default-deny limit blast radius. No behavioural detection |

## MITRE ATLAS

| Technique | Where it is exercised |
| --- | --- |
| AML.T0051 LLM Prompt Injection (direct and indirect) | `mcp_firewall.scanner`, `rag_guard.guard` |
| AML.T0057 LLM Data Leakage | `io_sanitization.dlp` |
| AML.T0053 LLM Plugin Compromise | `mcp_firewall.pinning`, `mcp_firewall.firewall` |
| AML.T0070 RAG Poisoning | `rag_guard.guard.ingest` |
| AML.T0029 Denial of ML Service / AML.T0034 Cost Harvesting | `agency_guard.circuit_breaker` |

Technique IDs are given as a navigation aid; confirm them against the current ATLAS
matrix before citing them in an audit.

## NIST

| Document | Relevant practice | Implementation |
| --- | --- | --- |
| AI 600-1 (Generative AI Profile) | Information security: prompt injection, data leakage; value chain and component integration | Firewall, DLP, pinning |
| AI 600-1 | Human-AI configuration: meaningful human oversight of consequential actions | Approval gate bound to the exact action |
| SP 800-218A (SSDF for generative AI) | PW.4, PS.2: verify integrity and provenance of acquired components | Tool digests, HMAC lock file, package allowlist |
| SP 800-218A | PW.8, RV.1: test for and track vulnerabilities continuously | Red-team corpus gating every pull request |
| SP 800-218A | PO.5: protect environments and secrets | Secrets from environment only; startup refuses weak keys |

## Coverage gaps, stated plainly

ASI07 is not covered. ASI10 is only mitigated by containment. Model-level risks
(training-data poisoning, model theft) are outside what a runtime proxy can address.
