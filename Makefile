setup:
	npm ci --ignore-scripts
	python3 -m venv .venv
	.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
	npm run build

check:
	PATH="$(CURDIR)/.venv/bin:$(PATH)" npm run verify
	.venv/bin/python -m ruff check app tests
	.venv/bin/python -m mypy app
	.venv/bin/python -m pytest

demo:
	.venv/bin/python -m app.cli demo

run:
	.venv/bin/python -m app.cli serve --demo
