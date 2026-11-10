# Contributing

## Setup

```bash
uv sync
```

```bash
make check
```

`make check` runs formatting, lint, strict type checking, the tests and the red-team
corpus. CI runs the same steps.

## Adding a control or a rule

1. Add the attack to the corpus first (`src/aegis/redteam/corpus/`) with
   `expect: blocked`, and confirm `uv run aegis redteam` now fails. A control without a
   failing case has not been shown to do anything.
2. Add at least one benign control (`expect: allowed`) close to the attack, so the rule
   cannot pass by over-blocking.
3. Implement the control. Return a `Finding` with a new, stable rule ID and the framework
   references it addresses.
4. Add unit tests for edge cases: empty input, boundary values, malformed input.

## Conventions

- Python 3.12+, full type hints, `mypy --strict` clean.
- Functions do one thing and stay under 40 lines.
- No magic numbers: constants at the top of the module or in configuration.
- Comments explain why a decision was made, not what the line does.
- Controls fail closed. If something cannot be parsed or verified, deny.
- No LLM calls in a decision path.
- Conventional commits (`feat:`, `fix:`, `chore:`, `refactor:`), one logical change each.
