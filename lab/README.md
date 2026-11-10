# Demonstration lab

Two ways to see the guards work against real payloads.

## 1. Browser

```bash
uv run aegis serve --lab
```

Open <http://127.0.0.1:8080/lab>. Every row is one case from the red-team corpus
(`src/aegis/redteam/corpus/`). Expand a row to see the exact payload, with invisible
characters made visible, then run it. Attacks should end `blocked`; benign controls
should end `allowed`. A red `GUARD FAILED` badge means a control regressed.

Lab mode generates random keys per process and builds a fresh, isolated environment
for every case. It also enables `/docs`. Do not expose a lab-mode instance to a network
you do not trust.

## 2. Command line

Scan a poisoned MCP server (three different poisoning techniques):

```bash
uv run aegis scan lab/poisoned_server_tools.json
```

Pin a clean server, then catch a rug pull:

```bash
export AEGIS_MANIFEST_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

```bash
uv run aegis pin lab/clean_server_tools.json --server weather --approved-by "$USER"
```

```bash
uv run aegis verify lab/clean_server_tools.json --server weather
```

Edit any description in `lab/clean_server_tools.json` and run `verify` again: the tool
is reported as `BLOCKED ... (mutated)` and the command exits non-zero.

Run the whole attack corpus the way CI does:

```bash
uv run aegis redteam
```
