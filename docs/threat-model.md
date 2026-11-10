# Threat model

## System and trust boundaries

| Component | Trust |
| --- | --- |
| Human user | Authenticated; trusted only for what their roles grant |
| Agent host and LLM | **Untrusted for authorisation.** Assumed to follow any instruction that reaches its context |
| MCP servers | Untrusted third-party code that can change at any time |
| Tool output, retrieved documents, web content | Untrusted data |
| Approver channel | Trusted, authenticated by an HMAC key the agent never sees |
| aegis-mcp process, its config and keys | Trusted computing base |

The central assumption: **a prompt injection will eventually succeed**. The controls are
built so that a fully compromised model still cannot exceed the user's authority, act on
high-impact tools unattended, exfiltrate through the common channels, or run forever.

## Attackers

1. **Malicious or compromised MCP server.** Controls tool metadata and tool output.
2. **Content author.** Plants instructions in a document, web page, ticket or email the
   agent will read.
3. **Low-privilege insider.** A legitimate user trying to make the agent use authority
   they do not hold.
4. **Other tenant.** A legitimate user of the same deployment trying to read another
   tenant's data.

Out of scope: an attacker with code execution in the aegis-mcp process, theft of the
signing keys, model-weight tampering, and denial of service against aegis-mcp itself.

## Threats and controls

| # | Threat | Control | Corpus cases |
| --- | --- | --- | --- |
| T1 | Tool description instructs the model to read local secrets and hide it | Pattern scan of all tool metadata; tool withheld | RT-MCP-001, 002 |
| T2 | Payload placed in parameter descriptions, defaults or enums to avoid review | Recursive schema scan | RT-MCP-003, 004 |
| T3 | Payload invisible to the reviewer (Unicode Tags, zero-width, bidi) | Hidden-character detection; rules re-run on stripped and decoded text | RT-MCP-005, 006, 007 |
| T4 | Covert parameter used as an exfiltration channel | Suspicious parameter names; closed-schema argument check | RT-MCP-008, 012 |
| T5 | One tool's description rewrites the use of another tool | Cross-tool shadowing rule | RT-MCP-009 |
| T6 | Server changes a tool after approval (rug pull) | sha256 pin over everything the model sees | RT-MCP-010 |
| T7 | Tool output carries instructions | Result scan before it enters the context | RT-MCP-015 |
| T8 | Agent uses its broad credentials for a user who lacks them (confused deputy) | RBAC on the human's verified roles only | RT-AG-001, 002, 003 |
| T9 | Forged, expired, unsigned or misdirected identity token | Pinned algorithm, required claims, audience and issuer checks | RT-AG-004 to 008 |
| T10 | Injected instruction triggers a destructive or irreversible action | High-impact tools require a human approval | RT-AG-009, 010 |
| T11 | Approval forged, self-issued, replayed, or reused for different arguments | HMAC signature, separation of duties, single use, call-digest binding | RT-AG-011 to 014 |
| T12 | Loop or token-draining attack | Step, depth, token and cost ceilings; state-hash loop detection | RT-AG-015 to 019 |
| T13 | Secret or PII in a response or reasoning trace | DLP redaction; reasoning dropped | RT-IO-001 to 008 |
| T14 | System prompt extraction | Canary strings redacted on egress | RT-IO-003 |
| T15 | Model output executed as a shell command | Metacharacter rejection, binary allowlist, forbidden flags | RT-IO-010 to 014 |
| T16 | Model output executed as SQL | AST validation; bind parameters required | RT-IO-020 to 025 |
| T17 | Zero-click exfiltration through a rendered image URL | Image host allowlist | RT-IO-030 to 033 |
| T18 | Model recommends a hallucinated or typosquatted package | Registry allowlist with edit-distance check | RT-IO-040 to 042 |
| T19 | Poisoned document stored in the knowledge base | Writer role, source allowlist, content scan at ingestion | RT-RAG-001 to 003 |
| T20 | Cross-tenant or cross-role retrieval | Structural partitioning plus retrieval-time re-assertion | RT-RAG-004, 005 |
| T21 | Index modified after ingestion | Per-chunk digest bound to tenant and source | RT-RAG-006 |

## Residual risk

- **Novel injection phrasing** passes the pattern rules. Mitigation: the pin and the
  default-deny posture do not depend on recognising the text, and high-impact actions
  still require a human.
- **Semantic exfiltration** through an allowed tool's legitimate parameters (for example
  a search query that encodes a secret). Schema validation narrows this; it does not
  remove it. Egress-capable tools should be classified high impact.
- **Approver fatigue.** A human who approves everything defeats the gate. The challenge
  shows the exact call; rate and scope of approvals should be monitored from the audit
  log.
- **Data-plane poisoning that is factually wrong but contains no instruction** is not
  detected. Source allowlisting and provenance fields support investigation.
- **Detector coverage** for secrets and PII is finite. Add organisation-specific
  patterns and canaries.
