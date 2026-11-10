# Agent instructions for aegis-mcp

Guidance for AI coding agents (Claude Code, Codex, Cursor and similar) working in this
repository. `CLAUDE.md` and `AGENTS.md` are kept identical; change both together.

Execute tasks fully: make the change, verify it, and report what was verified.

## What this project is

A zero-trust guard engine for MCP and agentic AI applications. See `README.md` for the
overview and `docs/architecture.md` for how the modules fit together.

## Non-negotiable design rules

- Controls are deterministic. No LLM call in any decision path.
- Fail closed. Input that cannot be parsed or verified is denied.
- Authorise the verified human user, never the agent's own credentials.
- Model output is untrusted input: parse it and check it against an allowlist.

## Code rules

1. Write production code, not prototypes. No TODO comments left behind.
2. Full type hints. `mypy --strict` must stay clean.
3. Name things explicitly: `validate_shell_command()`, not `check()`.
4. Functions do one thing and stay under 40 lines. If longer, extract.
5. Handle errors deliberately. Never let an exception pass silently.
6. No magic numbers. Constants at the top of the module or in configuration.
7. Comments explain why, not what.

## Stack

- Python 3.12+, managed with `uv` (`pyproject.toml` and `uv.lock`)
- FastAPI and Pydantic v2 for the API and all validation
- pytest for tests, ruff for format and lint, mypy for types

## Testing

- Every change to a control ships with tests.
- A new control starts as a failing case in `src/aegis/redteam/corpus/` with
  `expect: blocked`, plus a nearby benign case with `expect: allowed`.
- Test names describe behaviour: `test_rug_pull_is_blocked_even_when_new_text_looks_benign`.
- Cover edge cases: empty input, boundary values, malformed input.
- Coverage gate is 90%; keep changed lines covered.

Run everything before reporting done:

```bash
make check
```

## Git workflow

- Branches: `feat/...`, `fix/...`, `chore/...`, `refactor/...`
- Conventional commits (`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `ci:`)
- One logical change per commit
- Never push directly to `main`; always open a pull request

## Security

- Never commit API keys, tokens or passwords. Secrets come from the environment.
- Secret-shaped test fixtures are assembled from fragments at runtime
  (`src/aegis/redteam/lab.py`); do not add secret-shaped literals to the tree.
- Validate all external input with Pydantic models that forbid unknown fields.
- The lab front end writes attacker-controlled text with `textContent` only.
- Check a new dependency for known CVEs before adding it (`pip-audit` runs in CI).

## When stuck

1. Read the actual code; do not guess.
2. Follow existing patterns in the repository before introducing new ones.
3. If a task is ambiguous, make the most reasonable choice and note it.
4. Never leave broken code. If a test fails, fix it before finishing.

## Output

- Show the diff or the key changes, not whole files.
- Report test results as they are, including failures.
- If something cannot be done, explain why and propose an alternative.
- Keep summaries short.
