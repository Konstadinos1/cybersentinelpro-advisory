# aegis-mcp

[![CI](https://github.com/Konstadinos1/cybersentinelpro-advisory/actions/workflows/ci.yml/badge.svg)](https://github.com/Konstadinos1/cybersentinelpro-advisory/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Live demo: <https://aegis-mcp-steel.vercel.app>** (run the attacks against the real code in your browser)

A zero-trust security proxy, runtime guardrail engine and CI red-team suite for
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) and agentic AI applications.

An agent that can call tools is a program whose control flow is written by whoever
controls its input. Asking the model to "ignore malicious instructions" is not a
control. aegis-mcp puts **deterministic checks outside the model**, between the agent
host and everything it can touch: tools, databases, shells, vector stores and the user's
screen. No check in this repository calls an LLM.

![Attack lab: 79 cases run, 100% of attacks blocked, 100% of benign requests allowed](docs/images/lab-overview.png)

## What it does

| Module | Stops | Maps to |
| --- | --- | --- |
| [`mcp_firewall`](src/aegis/mcp_firewall) | Tool poisoning, advanced tool poisoning (payloads in parameter schemas and tool output), ASCII smuggling, rug-pull schema mutation, undeclared call arguments | LLM01, LLM04, ASI02, ASI04 |
| [`agency_guard`](src/aegis/agency_guard) | Confused deputy, unattended high-impact actions, approval replay and argument swapping, runaway loops and token draining | LLM03, LLM06, ASI01, ASI03, ASI08, ASI09 |
| [`io_sanitization`](src/aegis/io_sanitization) | Secrets, PII and system-prompt canaries in responses and reasoning traces; shell and SQL injection through model output; Markdown image exfiltration; slopsquatted packages | LLM02, LLM07, LLM08, LLM10, ASI05 |
| [`rag_guard`](src/aegis/rag_guard) | Cross-tenant retrieval, poisoned documents, tampered chunks, role bypass | LLM05, LLM09, ASI06 |
| [`redteam`](src/aegis/redteam) | Regressions in any of the above: 79 attack and control cases run on every pull request | NIST AI 600-1, SP 800-218A |

IDs refer to the OWASP Top 10 for LLM Applications 2026 and the OWASP Top 10 for Agentic
Applications. The full mapping, including MITRE ATLAS and NIST, is in
[docs/control-mapping.md](docs/control-mapping.md).

## Architecture

```mermaid
flowchart LR
    U[Human user] -->|identity token| H[Agent host / LLM]
    H -->|tools/list, tools/call| A

    subgraph A[aegis-mcp]
        direction TB
        F[MCP firewall<br/>scan + sha256 pin]
        G[Agency guard<br/>RBAC, budgets, approval]
        S[I/O sanitization<br/>DLP + sink validators]
        R[RAG guard<br/>tenant partitions]
    end

    A -->|approved tools only| M[MCP servers]
    A -->|validated argv / AST| X[Shell, SQL]
    A -->|tenant-scoped| V[Vector store]
    A -->|redacted| U
    P[Approver] -->|HMAC-signed verdict| G
```

Design rules that hold across the codebase:

- **Default deny.** Unknown tools are withheld, unknown roles get nothing, unknown
  tools are treated as high impact, unparseable input is rejected.
- **Authorise the human, not the agent.** Every decision uses the verified user's
  roles and tenant. The agent's own credentials are never consulted.
- **Bind approvals to exact actions.** A human approval covers one tool call with one
  argument digest, once.
- **Model output is untrusted input.** It is parsed (shlex, a SQL AST, a JSON Schema
  validator) and checked against an allowlist before it reaches a sink.
- **Explain every decision.** Controls return structured findings with a rule ID and
  framework references, and write a JSON audit event.

More detail: [docs/architecture.md](docs/architecture.md) and
[docs/threat-model.md](docs/threat-model.md).

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

Run the attack corpus against the guards:

```bash
uv run aegis redteam
```

Open the attack lab in a browser at <http://127.0.0.1:8080/lab>:

```bash
uv run aegis serve --lab
```

Scan an MCP server's tool definitions for poisoning:

```bash
uv run aegis scan lab/poisoned_server_tools.json
```

```text
HIGH     AEGIS-TP-002 add [description] Instruction to conceal behaviour from the user
CRITICAL AEGIS-TP-010 add [description] Reference to a sensitive local path or credential store
HIGH     AEGIS-TP-030 add [inputSchema/properties/sidenote] Covert side-channel parameter
HIGH     AEGIS-TP-005 get_fact [description] Cross-tool shadowing: description changes how another tool is used
HIGH     AEGIS-TP-001 search_docs [inputSchema/properties/query/description] Instruction override phrasing
...
```

**Full step-by-step instructions are in the [how-to-use guide](docs/usage.md)**: checking an MCP
server, running the service, approving high-impact calls, writing your own policy and
adding your own attack cases. A shorter lab walkthrough is in [lab/README.md](lab/README.md).

### Seeing what the reviewer cannot

Some payloads are invisible in any normal UI. The lab renders hidden code points so the
attack is legible. Here a tool description that displays as `Formats text.` carries the
instruction `ignore all previous instructions` in Unicode Tag characters:

![ASCII smuggling case with hidden characters revealed](docs/images/lab-ascii-smuggling.png)

## Using it as a library

```python
from aegis.mcp_firewall import McpFirewall, ToolCall, ToolManifest

firewall = McpFirewall(ToolManifest())

# 1. A human reviews the tool once; its sha256 is pinned.
firewall.approve_tool("weather-server", tool_definition, approved_by="carol")

# 2. Every later tools/list is filtered: poisoned, mutated or unapproved tools
#    never reach the model.
verdict = firewall.inspect_tools_list("weather-server", server_response["tools"])
safe_tools = verdict.allowed_tools

# 3. Every tools/call is validated against the pinned schema.
call = ToolCall(name="get_weather", arguments={"city": "Laval"})
assert firewall.inspect_tools_call("weather-server", call, tool_definition).allowed
```

```python
from aegis.io_sanitization import SqlPolicy, validate_sql

policy = SqlPolicy(allowed_tables=frozenset({"orders"}))
validate_sql("SELECT id FROM orders WHERE customer_id = %(id)s", policy).allowed  # True
validate_sql("SELECT id FROM orders WHERE customer_id = 7 OR 1 = 1", policy).allowed  # False
```

## HTTP API

`uv run aegis serve` exposes the same controls over HTTP for hosts not written in Python.
All `/v1` routes except the approval webhook require a bearer identity token.

| Route | Purpose |
| --- | --- |
| `POST /v1/mcp/tools/inspect` | Filter a `tools/list` result |
| `POST /v1/mcp/tools/approve` | Pin a reviewed tool (`security-admin` role) |
| `POST /v1/mcp/call/authorize` | Firewall, RBAC, budget and approval decision for one call |
| `POST /v1/mcp/result/inspect` | Scan tool output before it enters the context |
| `POST /v1/approvals/{id}` | HMAC-signed approval webhook |
| `POST /v1/output/sanitize` | DLP, reasoning removal, image stripping, package check |
| `POST /v1/sinks/shell`, `/v1/sinks/sql` | Validate a command or query |
| `POST /v1/rag/ingest`, `/v1/rag/query` | Tenant-scoped ingestion and retrieval |

Configuration is a YAML file ([default](src/aegis/default_config.yaml)); key material
comes only from the environment ([.env.example](.env.example)). Outside the demo modes the
service refuses to start with a missing or short secret.

The live site runs a third, narrower mode with the guard API switched off entirely. What it
exposes, and why that is safe to put online, is in [docs/deployment.md](docs/deployment.md).

## Red-team suite in CI

The corpus in [`src/aegis/redteam/corpus`](src/aegis/redteam/corpus) is plain YAML. Each
case names an attack, the payload, the expected outcome and the framework entries it
exercises. Benign controls sit alongside the attacks, so a rule that blocks everything
fails the build just as a rule that blocks nothing does.

```yaml
- id: RT-AG-013
  title: Arguments swapped after approval
  module: agency_guard
  kind: approval
  expect: blocked
  references: [OWASP-ASI09, OWASP-ASI02]
  input:
    tool: delete_file
    arguments: { path: tmp/cache.bin }
    swapped_arguments: { path: / }
    attack: argument_swap
```

`aegis redteam` exits non-zero on any missed attack or false positive and emits Markdown,
JUnit XML or JSON. The [CI workflow](.github/workflows/ci.yml) runs it on every pull
request, publishes the report to the job summary, and also runs lint, strict type
checking, the test suite on Python 3.12 and 3.13, and a dependency audit.

## Quality bar

| Check | Result |
| --- | --- |
| Tests | 428 passing (`uv run pytest`) |
| Coverage | 99% line and branch; build fails below 90% |
| Types | `mypy --strict`, no errors |
| Lint | `ruff` including the `S` (bandit) rule set |
| Red team | 79 cases: 66 attacks blocked, 13 benign controls allowed |
| Dependencies | `pip-audit` clean at time of writing |

Run all of it locally with `make check`.

## Limitations

This is a reference implementation. Read these before relying on it.

- **The poisoning scanner is heuristic.** It catches the documented techniques in the
  corpus; a novel phrasing can evade pattern rules. Pinning is the control that does not
  depend on recognising the attack, which is why unpinned tools are withheld by default.
- **State is in memory.** Circuit-breaker counters, pending approvals and the vector
  store do not survive a restart and are not shared between replicas. A production
  deployment needs a shared store behind the same interfaces.
- **Identity uses HS256 with a shared secret.** Suitable for a demo and for a single
  trust domain. Use asymmetric keys from your identity provider's JWKS in production.
- **The embedder is a feature hasher**, chosen so tests are repeatable and offline.
  Retrieval quality is not the point; the isolation and integrity checks are.
- **The SQL validator is conservative.** It rejects some safe queries (CTEs, unlisted
  functions) by design. Widen the policy deliberately.
- **Not independently audited.** See [SECURITY.md](SECURITY.md) to report a bypass.

## Repository layout

```text
src/aegis/
  core/              findings, canonical hashing, audit events
  mcp_firewall/      scanner, unicode smuggling detection, pinning, firewall
  agency_guard/      identity, RBAC policy, approval gate, circuit breaker
  io_sanitization/   detectors, DLP redactor, shell/SQL/markdown/package sinks
  rag_guard/         tenant store, ingestion and retrieval guard
  redteam/           corpus, lab environment, runner, reports
  api/               FastAPI app and the attack lab UI
  cli.py             aegis redteam | scan | pin | verify | approve | serve
tests/               428 tests, one per corpus case plus unit and API tests
lab/                 example poisoned and clean MCP servers, dev token helper, walkthrough
docs/                how-to-use guide, architecture, threat model, control mapping, deployment
main.py              entry point for the live demo site
```

## License

MIT. See [LICENSE](LICENSE).
