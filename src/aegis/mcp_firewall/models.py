"""Pydantic models for the subset of MCP that the firewall inspects."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.findings import Finding


class McpTool(BaseModel):
    """A tool as advertised by an MCP server in a ``tools/list`` result."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict, alias="inputSchema")

    def pinned_view(self) -> dict[str, Any]:
        """Everything the model is shown; this is what gets hashed.

        Extra fields (annotations, title, outputSchema) are included because
        they also reach the model and are a mutation channel.
        """
        return self.model_dump(by_alias=True, mode="json")


class ToolCall(BaseModel):
    """A ``tools/call`` request as issued by the agent host."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolVerdict(BaseModel):
    tool_name: str
    allowed: bool
    pin_status: str
    findings: list[Finding] = Field(default_factory=list)


class ToolsListVerdict(BaseModel):
    server_id: str
    allowed_tools: list[dict[str, Any]]
    verdicts: list[ToolVerdict]

    @property
    def blocked_tool_names(self) -> list[str]:
        return [verdict.tool_name for verdict in self.verdicts if not verdict.allowed]


class CallVerdict(BaseModel):
    tool_name: str
    allowed: bool
    findings: list[Finding] = Field(default_factory=list)
