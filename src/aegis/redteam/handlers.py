"""One handler per case kind. Each drives the real guard code, no mocks."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis.agency_guard import ApprovalError, StepUsage, sign_approval
from aegis.core.findings import Decision, Finding
from aegis.io_sanitization import strip_untrusted_images, validate_shell_command, validate_sql
from aegis.mcp_firewall import ToolCall
from aegis.redteam.lab import LAB_TENANT, OTHER_TENANT, TokenSigning, mint_token
from aegis.redteam.models import Outcome
from aegis.runtime import Services

Handler = Callable[[Services, dict[str, Any]], Outcome]

LAB_SERVER = "lab-server"
LAB_REVIEWER = "security-reviewer"
LAB_RUN = "lab-run"


def _rule_ids(findings: list[Finding]) -> tuple[str, ...]:
    return tuple(sorted({finding.rule_id for finding in findings}))


def _from_findings(blocked: bool, findings: list[Finding], fallback: str) -> Outcome:
    detail = "; ".join(f"{f.rule_id} {f.message}" for f in findings) or fallback
    return Outcome(blocked=blocked, detail=detail, rule_ids=_rule_ids(findings))


def tools_list(services: Services, data: dict[str, Any]) -> Outcome:
    """Advertise a tool, optionally after an earlier version was approved."""
    if data.get("approved"):
        services.firewall.approve_tool(LAB_SERVER, data["approved"], LAB_REVIEWER)
    verdict = services.firewall.inspect_tools_list(LAB_SERVER, [data["advertised"]]).verdicts[0]
    return _from_findings(not verdict.allowed, verdict.findings, "tool passed to the model")


def tools_call(services: Services, data: dict[str, Any]) -> Outcome:
    services.firewall.approve_tool(LAB_SERVER, data["approved"], LAB_REVIEWER)
    call = ToolCall(name=data["call"]["name"], arguments=data["call"].get("arguments", {}))
    verdict = services.firewall.inspect_tools_call(LAB_SERVER, call, data["approved"])
    return _from_findings(not verdict.allowed, verdict.findings, "call forwarded")


def tool_result(services: Services, data: dict[str, Any]) -> Outcome:
    verdict = services.firewall.inspect_tool_result("lab_tool", data["result"])
    return _from_findings(not verdict.allowed, verdict.findings, "result passed to the model")


def _step(data: dict[str, Any]) -> StepUsage:
    return StepUsage(tool_name=data["tool"], arguments=data.get("arguments", {}))


def authorize(services: Services, data: dict[str, Any]) -> Outcome:
    """A user with the given roles asks the agent to call a tool."""
    attack = data.get("token_attack", "")
    signing_attacks = {mode.value: mode for mode in TokenSigning}
    token = mint_token(
        services,
        data.get("subject", "alice"),
        data.get("roles", []),
        overrides=_token_overrides(attack),
        signing=signing_attacks.get(attack, TokenSigning.VALID),
    )
    decision = services.guard.evaluate(token, LAB_RUN, _step(data))
    return Outcome(blocked=decision.decision is not Decision.ALLOW, detail=decision.reason)


def _token_overrides(attack: str) -> dict[str, Any]:
    past = datetime.now(UTC) - timedelta(hours=1)
    overrides: dict[str, dict[str, Any]] = {
        "expired": {"exp": past, "iat": past - timedelta(minutes=5)},
        "wrong_audience": {"aud": "some-other-service"},
        "wrong_issuer": {"iss": "https://evil.example.net"},
    }
    return overrides.get(attack, {})


def approval(services: Services, data: dict[str, Any]) -> Outcome:
    """Exercise the HITL gate, honestly or with one of several attacks."""
    attack = data.get("attack", "none")
    requester = "alice"
    token = mint_token(services, requester, data.get("roles", ["operator"]))
    first = services.guard.evaluate(token, LAB_RUN, _step(data))
    if first.challenge is None:
        return Outcome(blocked=True, detail=f"no challenge issued: {first.reason}")
    approver = requester if attack == "self_approval" else LAB_REVIEWER
    key = b"k" * 32 if attack == "forged_signature" else services.secrets.approval_key.encode()
    signature = sign_approval(key, first.challenge, approver, "approve")
    try:
        services.guard.approvals.submit(
            first.challenge.challenge_id, approver, "approve", signature
        )
    except ApprovalError as error:
        return Outcome(blocked=True, detail=f"approval rejected: {error}")
    executed = dict(data)
    if attack == "argument_swap":
        executed["arguments"] = data["swapped_arguments"]
    second = services.guard.evaluate(token, LAB_RUN, _step(executed))
    if attack == "replay" and second.decision is Decision.ALLOW:
        second = services.guard.evaluate(token, LAB_RUN, _step(executed))
    return Outcome(blocked=second.decision is not Decision.ALLOW, detail=second.reason)


def circuit(services: Services, data: dict[str, Any]) -> Outcome:
    """Simulate an agent run and report whether the breaker tripped."""
    token = mint_token(services, "alice", ["viewer"])
    last_reason = "run completed within budget"
    for index in range(int(data["steps"])):
        arguments = {"q": "status"} if data.get("identical") else {"q": f"page-{index}"}
        step = StepUsage(
            tool_name="search_docs",
            arguments=arguments,
            recursion_depth=int(data.get("depth", 0)),
            tokens=int(data.get("tokens_per_step", 100)),
            cost_usd=float(data.get("cost_per_step", 0.001)),
        )
        decision = services.guard.evaluate(token, LAB_RUN, step)
        if decision.decision is Decision.DENY:
            return Outcome(blocked=True, detail=f"stopped at step {index + 1}: {decision.reason}")
        last_reason = decision.reason
    return Outcome(blocked=False, detail=last_reason)


def dlp(services: Services, data: dict[str, Any]) -> Outcome:
    """Blocked means none of the sensitive strings survive in the output."""
    result = services.dlp.sanitize_output(data["text"])
    leaked = [secret for secret in data.get("must_not_contain", []) if secret in result.text]
    if leaked:
        return Outcome(blocked=False, detail=f"{len(leaked)} sensitive value(s) leaked")
    return _from_findings(result.redacted, result.findings, "output unchanged")


def shell(services: Services, data: dict[str, Any]) -> Outcome:
    verdict = validate_shell_command(data["command"], services.config.sinks.shell)
    return _from_findings(not verdict.allowed, verdict.findings, "command accepted")


def sql(services: Services, data: dict[str, Any]) -> Outcome:
    verdict = validate_sql(data["query"], services.config.sinks.sql)
    return _from_findings(not verdict.allowed, verdict.findings, "query accepted")


def markdown(services: Services, data: dict[str, Any]) -> Outcome:
    verdict = strip_untrusted_images(data["text"], services.config.sinks.image_hosts)
    return _from_findings(not verdict.allowed, verdict.findings, "markdown unchanged")


def packages(services: Services, data: dict[str, Any]) -> Outcome:
    verdict = services.packages.verify_text(data["text"])
    return _from_findings(not verdict.allowed, verdict.findings, "all packages trusted")


def rag_ingest(services: Services, data: dict[str, Any]) -> Outcome:
    writer = services.verifier.verify(mint_token(services, "ingest-bot", ["rag-writer"]))
    result = services.rag.ingest(writer, chunk_id="doc-1", text=data["text"], source=data["source"])
    return _from_findings(not result.accepted, result.findings, "document ingested")


def rag_retrieve(services: Services, data: dict[str, Any]) -> Outcome:
    """Store a document for one tenant, then query as the configured reader."""
    owner_tenant = OTHER_TENANT if data.get("cross_tenant") else LAB_TENANT
    writer = services.verifier.verify(
        mint_token(services, "ingest-bot", ["rag-writer"], tenant_id=owner_tenant)
    )
    services.rag.ingest(
        writer,
        chunk_id="doc-1",
        text=data["document"],
        source="https://docs.example.com/handbook",
        allowed_roles=frozenset(data.get("document_roles", [])),
    )
    if data.get("tamper_with"):
        services.rag_store.tamper_for_test(owner_tenant, "doc-1", data["tamper_with"])
    reader = services.verifier.verify(mint_token(services, "bob", data.get("reader_roles", [])))
    result = services.rag.retrieve(reader, data["question"])
    if result.chunks:
        return Outcome(blocked=False, detail=f"{len(result.chunks)} chunk(s) returned")
    return _from_findings(True, result.findings, "no chunk visible to this user")


HANDLERS: dict[str, Handler] = {
    "tools_list": tools_list,
    "tools_call": tools_call,
    "tool_result": tool_result,
    "authorize": authorize,
    "approval": approval,
    "circuit": circuit,
    "dlp": dlp,
    "shell": shell,
    "sql": sql,
    "markdown": markdown,
    "packages": packages,
    "rag_ingest": rag_ingest,
    "rag_retrieve": rag_retrieve,
}
