"""Request and response bodies for the HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis.agency_guard import ApprovalChallenge
from aegis.core.findings import Decision, Finding
from aegis.io_sanitization import ReasoningMode

MAX_TEXT_CHARS = 200_000
MAX_TOOLS_PER_REQUEST = 500
IDENTIFIER_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"


class StrictModel(BaseModel):
    """Unknown fields are rejected so typos never silently disable a check."""

    model_config = ConfigDict(extra="forbid")


class InspectToolsRequest(StrictModel):
    server_id: str = Field(pattern=IDENTIFIER_PATTERN)
    tools: list[dict[str, Any]] = Field(max_length=MAX_TOOLS_PER_REQUEST)


class ApproveToolRequest(StrictModel):
    server_id: str = Field(pattern=IDENTIFIER_PATTERN)
    tool: dict[str, Any]


class ApproveToolResponse(BaseModel):
    tool_name: str
    sha256: str


class CallBody(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class AuthorizeCallRequest(StrictModel):
    server_id: str = Field(pattern=IDENTIFIER_PATTERN)
    run_id: str = Field(pattern=IDENTIFIER_PATTERN)
    tool: dict[str, Any]
    call: CallBody
    recursion_depth: int = Field(default=0, ge=0)
    tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0)


class AuthorizeCallResponse(BaseModel):
    decision: Decision
    reason: str
    findings: list[Finding] = Field(default_factory=list)
    challenge: ApprovalChallenge | None = None


class InspectResultRequest(StrictModel):
    tool_name: str = Field(min_length=1, max_length=128)
    result: Any


class ApprovalRequest(StrictModel):
    approver: str = Field(min_length=1, max_length=128)
    verdict: Literal["approve", "reject"]
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class ApprovalResponse(BaseModel):
    approved: bool


class SanitizeRequest(StrictModel):
    text: str = Field(max_length=MAX_TEXT_CHARS)
    reasoning_mode: ReasoningMode = ReasoningMode.DROP


class SanitizeResponse(BaseModel):
    text: str
    findings: list[Finding]


class ShellRequest(StrictModel):
    command: str = Field(max_length=4096)


class SqlRequest(StrictModel):
    query: str = Field(max_length=20_000)


class IngestRequest(StrictModel):
    chunk_id: str = Field(pattern=IDENTIFIER_PATTERN)
    text: str = Field(min_length=1, max_length=MAX_TEXT_CHARS)
    source: str = Field(min_length=1, max_length=2048)
    allowed_roles: frozenset[str] = frozenset()


class QueryRequest(StrictModel):
    question: str = Field(min_length=1, max_length=4096)
    top_k: int = Field(default=4, ge=1, le=20)


class QueryResponse(BaseModel):
    context: str
    sources: list[str]
    findings: list[Finding]
