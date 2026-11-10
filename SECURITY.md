# Security policy

## Reporting a vulnerability

A bypass of any control in this repository is a security bug. Examples: a tool
definition that reaches the model while carrying an instruction, a call that executes
without the approval the policy requires, a query that returns another tenant's data, or
a secret that survives redaction.

Please report privately through GitHub's **Report a vulnerability** button on the
Security tab of this repository. Do not open a public issue for an unpatched bypass.

Include the payload, the configuration used, and what you expected to happen. A failing
case in the corpus format (`src/aegis/redteam/corpus/*.yaml`) is the most useful report
there is: it becomes the regression test.

You can expect an acknowledgement within five business days.

## Scope

In scope: everything under `src/aegis`.

Out of scope: findings that require lab mode (`AEGIS_LAB_MODE=1`) to be enabled on an
exposed host. Lab mode is documented as unsafe for untrusted networks: it disables
authentication on the `/lab` routes and enables interactive API docs.

## Handling of secrets in this repository

No real credential is committed. Secret-shaped test fixtures are assembled from
fragments at runtime (`src/aegis/redteam/lab.py`) so that they exercise the detectors
without being valid or matching secret-scanner patterns in the source tree.
