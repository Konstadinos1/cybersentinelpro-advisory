"""HTTP surface of the guard engine."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from aegis.agency_guard import ApprovalError, StepUsage
from aegis.api import schemas
from aegis.api.deps import AdminDep, IdentityDep, ServicesDep, TokenDep
from aegis.core.findings import Decision
from aegis.io_sanitization import (
    SinkVerdict,
    strip_untrusted_images,
    validate_shell_command,
    validate_sql,
)
from aegis.mcp_firewall import CallVerdict, ToolCall, ToolsListVerdict
from aegis.rag_guard import IngestionResult

router = APIRouter(prefix="/v1")


@router.post("/mcp/tools/inspect", tags=["mcp-firewall"])
def inspect_tools(
    body: schemas.InspectToolsRequest, services: ServicesDep, _: IdentityDep
) -> ToolsListVerdict:
    """Filter a ``tools/list`` result down to clean, pinned tools."""
    return services.firewall.inspect_tools_list(body.server_id, body.tools)


@router.post("/mcp/tools/approve", tags=["mcp-firewall"])
def approve_tool(
    body: schemas.ApproveToolRequest, services: ServicesDep, admin: AdminDep
) -> schemas.ApproveToolResponse:
    """Pin a reviewed tool. Requires the security-admin role."""
    try:
        digest = services.firewall.approve_tool(body.server_id, body.tool, admin.subject)
    except PermissionError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "malformed tool") from error
    return schemas.ApproveToolResponse(tool_name=str(body.tool.get("name")), sha256=digest)


@router.post("/mcp/call/authorize", tags=["agency-guard"])
def authorize_call(
    body: schemas.AuthorizeCallRequest, services: ServicesDep, token: TokenDep
) -> schemas.AuthorizeCallResponse:
    """Firewall the call, then apply RBAC, budgets and the approval gate."""
    call = ToolCall(name=body.call.name, arguments=body.call.arguments)
    verdict = services.firewall.inspect_tools_call(body.server_id, call, body.tool)
    if not verdict.allowed:
        return schemas.AuthorizeCallResponse(
            decision=Decision.DENY, reason="blocked by MCP firewall", findings=verdict.findings
        )
    step = StepUsage(
        tool_name=call.name,
        arguments=call.arguments,
        recursion_depth=body.recursion_depth,
        tokens=body.tokens,
        cost_usd=body.cost_usd,
    )
    decision = services.guard.evaluate(token, body.run_id, step)
    return schemas.AuthorizeCallResponse(
        decision=decision.decision, reason=decision.reason, challenge=decision.challenge
    )


@router.post("/mcp/result/inspect", tags=["mcp-firewall"])
def inspect_result(
    body: schemas.InspectResultRequest, services: ServicesDep, _: IdentityDep
) -> CallVerdict:
    """Scan tool output before it is appended to the model context."""
    return services.firewall.inspect_tool_result(body.tool_name, body.result)


@router.post("/approvals/{challenge_id}", tags=["agency-guard"])
def submit_approval(
    challenge_id: str, body: schemas.ApprovalRequest, services: ServicesDep
) -> schemas.ApprovalResponse:
    """Signed webhook for approvers. The HMAC signature is the authentication."""
    try:
        approved = services.guard.approvals.submit(
            challenge_id, body.approver, body.verdict, body.signature
        )
    except ApprovalError as error:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
    return schemas.ApprovalResponse(approved=approved)


@router.post("/output/sanitize", tags=["io-sanitization"])
def sanitize_output(
    body: schemas.SanitizeRequest, services: ServicesDep, _: IdentityDep
) -> schemas.SanitizeResponse:
    """Redact secrets and reasoning, strip exfiltration images, vet packages."""
    redacted = services.dlp.sanitize_output(body.text, body.reasoning_mode)
    images = strip_untrusted_images(redacted.text, services.config.sinks.image_hosts)
    packages = services.packages.verify_text(redacted.text)
    return schemas.SanitizeResponse(
        text=str(images.safe_value),
        findings=redacted.findings + images.findings + packages.findings,
    )


@router.post("/sinks/shell", tags=["io-sanitization"])
def check_shell(body: schemas.ShellRequest, services: ServicesDep, _: IdentityDep) -> SinkVerdict:
    return validate_shell_command(body.command, services.config.sinks.shell)


@router.post("/sinks/sql", tags=["io-sanitization"])
def check_sql(body: schemas.SqlRequest, services: ServicesDep, _: IdentityDep) -> SinkVerdict:
    return validate_sql(body.query, services.config.sinks.sql)


@router.post("/rag/ingest", tags=["rag-guard"])
def rag_ingest(
    body: schemas.IngestRequest, services: ServicesDep, identity: IdentityDep
) -> IngestionResult:
    """Ingest into the caller's own tenant; the tenant comes from the token."""
    return services.rag.ingest(
        identity,
        chunk_id=body.chunk_id,
        text=body.text,
        source=body.source,
        allowed_roles=body.allowed_roles,
    )


@router.post("/rag/query", tags=["rag-guard"])
def rag_query(
    body: schemas.QueryRequest, services: ServicesDep, identity: IdentityDep
) -> schemas.QueryResponse:
    result = services.rag.retrieve(identity, body.question, body.top_k)
    return schemas.QueryResponse(
        context=result.context,
        sources=[item.chunk.source for item in result.chunks],
        findings=result.findings,
    )
