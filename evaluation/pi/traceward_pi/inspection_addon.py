"""Loaded only by the optional observer-side mitmdump interpreter."""
import os
from pathlib import Path
from traceward_pi.http_capture import Capture

addons = [Capture(Path(os.environ['TRACEWARD_HTTP_EVENTS']))]
