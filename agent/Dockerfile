# The bundled agent under test. Its base image and dependency versions are
# pinned to the build that produced the published results (see
# constraints.txt): both are measurement-affecting.
FROM python:3.11.16-slim-trixie

LABEL org.opencontainers.image.title="creuset-agent" \
      org.opencontainers.image.description="Creuset's bundled LangChain agent (naive / hardened / broken variants)" \
      org.opencontainers.image.source="https://github.com/jackson-gits/Creuset" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AGENT_VARIANT=hardened

WORKDIR /app

# Dependencies first (layer caching). No apt packages: the healthcheck uses the
# image's own Python, so there is no curl in a container that runs hijackable code.
COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

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
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

# Default: one-shot scenario mode (the harness passes --scenario-file ...).
ENTRYPOINT ["python", "run_agent.py"]
CMD ["--help"]
