# The live demo site

**<https://aegis-mcp-steel.vercel.app>**

A landing page at `/` and the attack lab at `/lab`. Every "Run" click executes a case from
the shipped corpus against the real guard code on the server and returns the verdict.

## What is and is not exposed

The site runs in **public demo mode**, which is narrower than the local lab mode.

| | Production | Lab (`--lab`) | Public demo (`--public-demo`) |
| --- | --- | --- | --- |
| Guard API (`/v1/...`) | yes, token required | yes | **not mounted** |
| Landing page and attack lab | no | yes | yes |
| Interactive API docs, OpenAPI schema | no | yes | **not mounted** |
| Rate limit on running cases | n/a | none | 240 per minute per client (see below) |
| Keys | from the environment | random per process | random per process |
| Intended for | real deployments | your own machine | the internet |

Why the lab is safe to put online:

- A visitor chooses only **which** shipped case runs. The run endpoint takes a case ID
  from a fixed table and ignores any request body, so nothing a visitor sends reaches a
  guard.
- Every run builds a fresh environment with throwaway keys. There is no state to corrupt
  and no secret to steal.
- The guard API is absent, so the demo cannot be used as an open scanner or as a way to
  probe the controls with custom payloads. Do that locally.
- Pages carry a strict Content-Security-Policy with no inline script or style, and the
  front end writes all case text with `textContent`.

## How it is deployed

- Host: Vercel, project `aegis-mcp`, linked to this repository.
- Entry point: [`main.py`](../main.py) at the repository root, named in
  `[tool.vercel]` in `pyproject.toml`. It builds the app in public demo mode.
- Every push to `main` deploys to production. Every other branch and pull request gets
  its own preview URL (previews require a Vercel login).
- No environment variables or secrets are configured on the host. The demo needs none.

## The rate limit and its limits

Running a case is cheap (a few milliseconds), but a public endpoint that does work should
still be bounded. The app allows each client 240 case runs a minute, enough for three full
passes of the corpus. Past that it answers `429` with `Retry-After`, and the page says so.

**Measured on the live site, this limit is only partly effective on Vercel:**

| Traffic from one address | Result |
| --- | --- |
| 600 runs, one at a time (how the lab page behaves) | 277 allowed, then refused with `429` |
| 1,200 runs, 10 in parallel | all 1,200 allowed |

The limiter counts in the memory of one server instance. Under parallel load Vercel
starts more instances, each with its own count, so a client that sends requests in
parallel is not held to the limit. Ordinary visitors are; a deliberate flood is not.

What that means in practice: the demo has no data to steal and no state to corrupt, so
the exposure is compute. On a Vercel Hobby plan a flood can exhaust the plan's included
usage and get the project paused, not billed. To close the gap, add one rule in the Vercel
dashboard (project, then Firewall, then Add rule):

- If: request path starts with `/lab/api/cases/` and method equals `POST`
- Then: rate limit, fixed window, 60 seconds, 240 requests, keyed by IP, action `429`

That rule is enforced at the edge before any instance runs, so it holds under parallel
load. It could not be created through the API for this project, so it is a manual step.

The client address comes from `X-Forwarded-For`, which Vercel overwrites with the real
address. `main.py` opts into that header explicitly. Anywhere else the header is
client-controlled, so it is ignored unless you name it with `AEGIS_CLIENT_IP_HEADER`.

## Run the same thing locally

```bash
uv run aegis serve --public-demo
```

Then open <http://127.0.0.1:8080>.

## Deploy your own copy

1. Fork the repository.
2. In Vercel, create a project from the fork. No settings need changing: the entry point
   and Python version come from `pyproject.toml`.
3. Push to `main`.
