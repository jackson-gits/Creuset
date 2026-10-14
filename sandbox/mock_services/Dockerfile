FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Unprivileged: the fake worlds and audit log live in memory, nothing on disk.
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin mock
USER mock

HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
