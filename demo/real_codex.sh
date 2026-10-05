#!/bin/sh
# Run from the host checkout. Managed Docker/gVisor setup is automatic.
set -eu
exec python3 "$(dirname "$0")/validate.py" --cases "${TRACEWARD_REAL_CASE:-disguised}" "$@"
