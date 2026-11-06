FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY harness/harness.py /app/harness.py

# The runner uses only the Python standard library.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin runner
USER 10001:10001

ENTRYPOINT ["python", "/app/harness.py"]
