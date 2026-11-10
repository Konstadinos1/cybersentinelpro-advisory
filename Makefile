.PHONY: install lint typecheck test redteam check lab

install:
	uv sync

lint:
	uv run ruff format --check .
	uv run ruff check .

typecheck:
	uv run mypy

test:
	uv run pytest

redteam:
	uv run aegis redteam --format markdown --output reports/redteam.md

check: lint typecheck test redteam

lab:
	uv run aegis serve --lab
