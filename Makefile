PYTHON ?= .venv/bin/python
DASHBOARD_PID_FILE := .dashboard.pid

.PHONY: dashboard dashboard-stop

dashboard:
	@if [ -f "$(DASHBOARD_PID_FILE)" ]; then \
		pid=$$(cat "$(DASHBOARD_PID_FILE)"); \
		case "$$pid" in ''|*[!0-9]*) ;; *) \
			case "$$(ps -p "$$pid" -o command= 2>/dev/null)" in \
				*" -m traceward.cli dashboard"*) \
					echo "Dashboard already running (PID $$pid). Use make dashboard-stop."; exit 1 ;; \
			esac ;; \
		esac; \
	fi; \
	$(PYTHON) -m traceward.cli dashboard $(DASHBOARD_ARGS) & \
	pid=$$!; \
	trap 'rm -f "$(DASHBOARD_PID_FILE)"' EXIT; \
	trap 'kill -TERM "$$pid" 2>/dev/null || :; wait "$$pid"; exit 130' INT; \
	trap 'kill -TERM "$$pid" 2>/dev/null || :; wait "$$pid"; exit 143' TERM; \
	printf '%s\n' "$$pid" > "$(DASHBOARD_PID_FILE)"; \
	wait "$$pid"; \
	status=$$?; \
	case "$$status" in 0|143) exit 0 ;; *) exit "$$status" ;; esac

dashboard-stop:
	@if [ ! -f "$(DASHBOARD_PID_FILE)" ]; then \
		echo "No dashboard started by make is running."; exit 0; \
	fi; \
	pid=$$(cat "$(DASHBOARD_PID_FILE)"); \
	case "$$pid" in ''|*[!0-9]*) \
		rm -f "$(DASHBOARD_PID_FILE)"; \
		echo "Removed invalid dashboard PID file."; exit 0 ;; \
	esac; \
	case "$$(ps -p "$$pid" -o command= 2>/dev/null)" in \
		*" -m traceward.cli dashboard"*) \
			kill -TERM "$$pid"; \
			echo "Stopping dashboard (PID $$pid)." ;; \
		*) \
			rm -f "$(DASHBOARD_PID_FILE)"; \
			echo "Dashboard is not running; removed stale PID file." ;; \
	esac
