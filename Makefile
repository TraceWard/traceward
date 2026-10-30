PYTHON ?= .venv/bin/python

.PHONY: dashboard

dashboard:
	docker compose up -d --build
