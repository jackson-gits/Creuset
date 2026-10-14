# Standard library only: builds without network access and runs without a key.
FROM python:3.11.16-slim-trixie

LABEL org.opencontainers.image.title="creuset-example-scripted" \
      org.opencontainers.image.description="Deterministic example agent for Creuset's agent contract" \
      org.opencontainers.image.source="https://github.com/jackson-gits/Creuset" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY agent.py .
RUN useradd --uid 10004 --no-create-home --shell /usr/sbin/nologin agent
USER agent
ENTRYPOINT ["python", "agent.py"]
