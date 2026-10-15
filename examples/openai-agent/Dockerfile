# A real-LLM agent on Creuset's contract. The openai version is the one the
# bundled agent is pinned to (agent/constraints.txt).
FROM python:3.11.16-slim-trixie

LABEL org.opencontainers.image.title="creuset-example-openai" \
      org.opencontainers.image.description="Minimal OpenAI-SDK agent for Creuset's agent contract" \
      org.opencontainers.image.source="https://github.com/jackson-gits/Creuset" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN pip install --no-cache-dir openai==1.109.1
COPY agent.py .
RUN useradd --uid 10005 --no-create-home --shell /usr/sbin/nologin agent
USER agent
ENTRYPOINT ["python", "agent.py"]
