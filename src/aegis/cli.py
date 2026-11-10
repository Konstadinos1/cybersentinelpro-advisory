"""Command-line interface: red-team runs, tool scanning, pinning, approvals."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aegis.agency_guard import ApprovalChallenge, sign_approval
from aegis.core.findings import Severity, worst_severity
from aegis.mcp_firewall import (
    ManifestError,
    McpFirewall,
    ToolManifest,
    load_manifest,
    save_manifest,
)
from aegis.mcp_firewall.firewall import BLOCKING_SEVERITY
from aegis.mcp_firewall.models import McpTool
from aegis.mcp_firewall.scanner import scan_tool
from aegis.redteam import RENDERERS, CorpusError, load_corpus, run_suite
from aegis.runtime import ENV_PREFIX

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
DEFAULT_MANIFEST = "aegis.lock.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


class CliError(Exception):
    """A user-facing error; printed without a traceback."""


def _env_key(name: str) -> bytes:
    value = os.environ.get(ENV_PREFIX + name, "")
    if not value:
        raise CliError(f"environment variable {ENV_PREFIX}{name} is required")
    return value.encode("utf-8")


def _read_tools(path: Path) -> list[dict[str, Any]]:
    """Accept a bare list, ``{"tools": [...]}`` or a JSON-RPC ``tools/list`` result."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CliError(f"cannot read {path}: {error}") from error
    if isinstance(document, dict):
        document = document.get("result", document).get("tools", [])
    if not isinstance(document, list):
        raise CliError(f"{path} does not contain a list of tools")
    return document


def cmd_redteam(args: argparse.Namespace) -> int:
    try:
        cases = load_corpus(Path(args.corpus) if args.corpus else None)
    except CorpusError as error:
        raise CliError(str(error)) from error
    report = run_suite(cases)
    rendered = RENDERERS[args.format](report)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    summary = (
        f"{len(report.results)} cases, {len(report.failures)} failed, "
        f"attacks blocked {report.attack_block_rate:.0%}, "
        f"benign allowed {report.benign_pass_rate:.0%}\n"
    )
    sys.stderr.write(summary)
    return EXIT_FINDINGS if report.failures else EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    """Static scan only; needs no keys, so it suits pre-commit and CI."""
    worst = Severity.INFO
    for raw_tool in _read_tools(Path(args.tools)):
        tool = McpTool.model_validate(raw_tool)
        findings = scan_tool(tool)
        worst = max(worst, worst_severity(findings))
        for finding in findings:
            sys.stdout.write(
                f"{finding.severity.name:8} {finding.rule_id} {tool.name} "
                f"[{finding.location}] {finding.message}\n"
            )
    return EXIT_FINDINGS if worst >= BLOCKING_SEVERITY else EXIT_OK


def _open_manifest(path: Path, key: bytes) -> ToolManifest:
    return load_manifest(path, key) if path.exists() else ToolManifest()


def cmd_pin(args: argparse.Namespace) -> int:
    key = _env_key("MANIFEST_KEY")
    path = Path(args.manifest)
    firewall = McpFirewall(_open_manifest(path, key))
    for raw_tool in _read_tools(Path(args.tools)):
        try:
            digest = firewall.approve_tool(args.server, raw_tool, args.approved_by)
        except PermissionError as error:
            raise CliError(str(error)) from error
        sys.stdout.write(f"pinned {raw_tool.get('name')} sha256:{digest}\n")
    save_manifest(firewall.manifest, path, key)
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    firewall = McpFirewall(load_manifest(Path(args.manifest), _env_key("MANIFEST_KEY")))
    verdict = firewall.inspect_tools_list(args.server, _read_tools(Path(args.tools)))
    for tool in verdict.verdicts:
        state = "ok" if tool.allowed else "BLOCKED"
        sys.stdout.write(f"{state:8} {tool.tool_name} ({tool.pin_status})\n")
    return EXIT_FINDINGS if verdict.blocked_tool_names else EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    """Sign a pending challenge; the output is posted to the approval webhook."""
    try:
        document = json.loads(Path(args.challenge).read_text(encoding="utf-8"))
        challenge = ApprovalChallenge.model_validate(document)
    except (OSError, ValueError) as error:
        raise CliError(f"cannot read challenge: {error}") from error
    signature = sign_approval(_env_key("APPROVAL_KEY"), challenge, args.approver, args.verdict)
    body = {"approver": args.approver, "verdict": args.verdict, "signature": signature}
    sys.stdout.write(json.dumps(body) + "\n")
    return EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn  # noqa: PLC0415 - keeps CLI start-up fast for non-server commands

    if args.lab:
        os.environ[ENV_PREFIX + "LAB_MODE"] = "1"
    uvicorn.run("aegis.api.app:app_from_environment", factory=True, host=args.host, port=args.port)
    return EXIT_OK


def _add_tool_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("tools", help="JSON file with a tools/list result")
    parser.add_argument("--server", required=True, help="MCP server identifier")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)


def _add_redteam_and_scan(commands: Any) -> None:
    redteam = commands.add_parser("redteam", help="run the attack corpus against the guards")
    redteam.add_argument("--format", choices=sorted(RENDERERS), default="markdown")
    redteam.add_argument("--output", help="write the report to this file")
    redteam.add_argument("--corpus", help="directory of *.yaml case files")
    redteam.set_defaults(handler=cmd_redteam)

    scan = commands.add_parser("scan", help="scan MCP tool definitions for poisoning")
    scan.add_argument("tools", help="JSON file with a tools/list result")
    scan.set_defaults(handler=cmd_scan)


def _add_pinning(commands: Any) -> None:
    pin = commands.add_parser("pin", help="approve tools and write the lock file")
    _add_tool_arguments(pin)
    pin.add_argument("--approved-by", required=True)
    pin.set_defaults(handler=cmd_pin)

    verify = commands.add_parser("verify", help="check tools against the lock file")
    _add_tool_arguments(verify)
    verify.set_defaults(handler=cmd_verify)


def _add_approve_and_serve(commands: Any) -> None:
    approve = commands.add_parser("approve", help="sign a human-approval challenge")
    approve.add_argument("challenge", help="JSON file containing the challenge")
    approve.add_argument("--approver", required=True)
    approve.add_argument("--verdict", choices=["approve", "reject"], default="approve")
    approve.set_defaults(handler=cmd_approve)

    serve = commands.add_parser("serve", help="run the HTTP API")
    serve.add_argument("--host", default=DEFAULT_HOST)
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--lab", action="store_true", help="enable the attack lab UI")
    serve.set_defaults(handler=cmd_serve)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    _add_redteam_and_scan(commands)
    _add_pinning(commands)
    _add_approve_and_serve(commands)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except (CliError, ManifestError) as error:
        sys.stderr.write(f"error: {error}\n")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
