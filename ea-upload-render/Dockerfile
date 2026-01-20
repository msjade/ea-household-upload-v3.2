FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY ea-upload-render/app/api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ea-upload-render/app/api/main.py .
COPY ea-upload-render/app/api/templates ./templates

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
