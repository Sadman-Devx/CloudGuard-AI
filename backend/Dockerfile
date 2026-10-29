# Build from the repository root so sample_data/ is available:
#   docker build -f backend/Dockerfile -t cloudguard-backend .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG REQUIREMENTS=production
WORKDIR /app/backend

COPY backend/requirements ./requirements
RUN pip install -r requirements/${REQUIREMENTS}.txt

COPY backend ./
COPY sample_data /app/sample_data

ENV FIXTURES_DIR=/app/sample_data/aws \
    DJANGO_SETTINGS_MODULE=config.settings.production

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
