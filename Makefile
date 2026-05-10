.PHONY: install test lint

install:
	@pip install -e '.[dev]'

test:
	@python -m pytest -q

lint:
	@ruff check .
