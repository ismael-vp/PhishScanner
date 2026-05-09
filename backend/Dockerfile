# PhishingScanner Backend - Production Dockerfile
FROM python:3.11-slim

# Evitar que Python genere archivos .pyc y forzar logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Instalar Tesseract OCR y dependencias de imagen
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY . .

# Comando de inicio para Render (Usa el puerto dinámico de Render)
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
