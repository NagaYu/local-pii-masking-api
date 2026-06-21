# syntax=docker/dockerfile:1

# --------------------------------------------------------------------------- #
# Build stage: install dependencies into an isolated prefix.
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY requirements.txt .
RUN python -m pip install --upgrade pip \
    && python -m pip install --prefix=/install -r requirements.txt

# --------------------------------------------------------------------------- #
# Runtime stage: minimal image, non-root, no build toolchain.
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PII_SESSION_TTL_SECONDS=3600 \
    PII_MAX_SESSIONS=10000

# Create an unprivileged user to run the service.
RUN groupadd --system app && useradd --system --gid app --no-create-home app

WORKDIR /app

# Bring in the pre-built dependencies from the builder stage.
COPY --from=builder /install /usr/local

# Copy only the application package.
COPY app ./app

USER app

EXPOSE 8080

# Container-native health check hitting the local /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f'http://127.0.0.1:{os.getenv(\"PORT\",\"8080\")}/health'; \
sys.exit(0 if urllib.request.urlopen(url, timeout=2).status==200 else 1)" \
    || exit 1

# Single-process by default; scale horizontally with more containers.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
