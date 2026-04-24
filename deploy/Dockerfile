# syntax=docker/dockerfile:1.7
# Multi-stage build: deps cached in a builder, runtime image is slim.

# --- Builder -------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# System build deps (remove if pure-python wheels are enough — they are for us).
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --prefix=/install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt && \
    pip install --prefix=/install "psycopg[binary]>=3.2"

# --- Runtime -------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEEPSEC_HOST=0.0.0.0 \
    DEEPSEC_PORT=5000

# Non-root user — we do not run a scanner as root.
RUN groupadd --system deepsec && useradd --system --gid deepsec --home /app deepsec

WORKDIR /app

COPY --from=builder /install /usr/local

# Copy only what the runtime needs.
COPY deepsecurity/ ./deepsecurity/
COPY pyproject.toml requirements.txt README.md ./

# Writable runtime dirs owned by the non-root user.
RUN install -d -o deepsec -g deepsec /app/data /app/quarantine /app/safelist /app/deleted /app/logs /app/models

USER deepsec

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)" || exit 1

# Gunicorn for production. Single worker by default — the scanner is CPU-bound
# per-request and holds in-process state; scale horizontally with more replicas.
CMD ["gunicorn", \
     "--bind=0.0.0.0:5000", \
     "--workers=1", \
     "--threads=4", \
     "--access-logfile=-", \
     "--error-logfile=-", \
     "deepsecurity.api:create_app()"]
