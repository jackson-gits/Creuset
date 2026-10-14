FROM python:3.11.16-slim-trixie

LABEL org.opencontainers.image.title="creuset-mock-services" \
      org.opencontainers.image.description="Creuset's per-run fake world and server-side audit log" \
      org.opencontainers.image.source="https://github.com/jackson-gits/Creuset" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt constraints.txt ./
RUN pip install --no-cache-dir -r requirements.txt -c constraints.txt

COPY main.py .

# Unprivileged: the fake worlds and audit log live in memory, nothing on disk.
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin mock
USER mock

# Python rather than curl: the harness reaches this container through
# `docker exec ... python`, so Python is the one tool it must keep anyway.
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2)"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
