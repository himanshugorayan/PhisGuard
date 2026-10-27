FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY backend/static ./static
COPY backend/models ./models

RUN useradd --create-home appuser && chown -R appuser /srv
USER appuser

EXPOSE 8000
# $PORT is injected by Render/Railway/Fly; defaults to 8000 locally
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
