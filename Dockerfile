FROM python:3.12-slim

# Nicht als root laufen
RUN useradd --create-home --uid 1000 appuser

WORKDIR /app

# Abhaengigkeiten zuerst (bessere Layer-Cache-Nutzung)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Anwendungscode
COPY app.py .

USER appuser

EXPOSE 8001

# Produktions-WSGI-Server; TOTP-Validierung erfolgt serverseitig in app.py
CMD ["gunicorn", "--bind", "0.0.0.0:8001", "--workers", "2", "app:app"]
