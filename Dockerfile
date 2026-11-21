FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY audit ./audit
COPY miner.yaml ./miner.yaml

RUN useradd -m app && chown -R app /app
USER app

EXPOSE 8000
# $PORT is injected by Render/Railway/Fly; default 8000 locally.
# One worker keeps the in-memory audit cache coherent.
CMD ["sh", "-c", "uvicorn audit.app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --timeout-keep-alive 30"]
