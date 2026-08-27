FROM python:3.11-slim

WORKDIR /app

# Install OS-level dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent source
COPY . .

# Health check — the agent exposes a minimal HTTP server for readiness probing
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default entrypoint for scenario execution mode.
# The gate harness overrides CMD to pass --scenario-file.
# For long-running service mode (blue/green slot), run serve.py instead.
ENTRYPOINT ["python", "run_agent.py"]
CMD ["--help"]
