PYTHON ?= .venv/bin/python

.PHONY: dashboard

dashboard:
	$(PYTHON) -m traceward.cli dashboard $(DASHBOARD_ARGS)
