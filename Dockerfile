FROM python:3.12-slim AS backend
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[server]'
RUN useradd --create-home --uid 10001 traceward
USER traceward
EXPOSE 8000
CMD ["python", "-m", "traceward.backend", "--host", "0.0.0.0", "--port", "8000"]

FROM node:22-alpine AS ui-build
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM nginx:alpine AS ui
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=ui-build /build/src/traceward/dashboard_assets /usr/share/nginx/html
EXPOSE 80
