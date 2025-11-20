FROM python:3.11-slim

WORKDIR /app

COPY webhook.py .

RUN pip install fastapi uvicorn

CMD ["uvicorn", "webhook:app", "--host", "0.0.0.0", "--port", "8080"]
