FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/deploy/docker-entrypoint.sh /app/deploy/worker-entrypoint.sh \
    && chown -R app:app /app
COPY . .
RUN chmod +x /app/deploy/docker-entrypoint.sh /app/deploy/worker-entrypoint.sh \
    && chown -R app:app /app

ENV PYTHONPATH=/app

USER app
EXPOSE 8000
CMD ["/app/deploy/docker-entrypoint.sh"]
USER app
EXPOSE 8000
CMD ["/app/deploy/docker-entrypoint.sh"]
