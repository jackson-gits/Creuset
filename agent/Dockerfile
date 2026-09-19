FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AGENT_VARIANT=hardened

WORKDIR /app

# curl is only used by the HEALTHCHECK in service (blue/green slot) mode
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user. The sandbox also runs the container with
# --read-only, --cap-drop ALL and no-new-privileges (see sandbox/run_test.py).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent \
    && mkdir -p /app/live_traffic && chown agent /app/live_traffic
USER agent

# Service mode (blue/green slots) is started by docker-compose with
#   uvicorn serve:app --host 0.0.0.0 --port 8000
# The sandbox harness disables this check (--no-healthcheck) for one-shot runs.
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: one-shot scenario mode (the harness passes --scenario-file ...).
ENTRYPOINT ["python", "run_agent.py"]
CMD ["--help"]
