# Optional observer-side TLS inspection. No CA key or proxy runs in the guest.
ARG PI_BASE_IMAGE=traceward-pi:0.85.1-lab4
FROM ${PI_BASE_IMAGE}
ENV UV_PYTHON_INSTALL_DIR=/opt/inspection-python \
    UV_TOOL_DIR=/opt/inspection-tools \
    UV_TOOL_BIN_DIR=/opt/inspection-bin
RUN pip install --no-cache-dir uv==0.13.4 \
 && uv tool install --python 3.13 mitmproxy==12.2.3 \
 && /opt/inspection-bin/mitmdump --version
