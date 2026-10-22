FROM python:3.12-slim

# Eigener Benutzer: Der Prozess braucht keine root-Rechte - im Container wäre
# root sonst gleichbedeutend mit "darf alles im Container".
RUN useradd --create-home --uid 10001 app

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app *.py ./
COPY --chown=app:app templates templates
COPY --chown=app:app static static

USER app

EXPOSE 5000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
