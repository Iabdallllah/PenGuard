FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn

COPY target_app.py /app/target_app.py

EXPOSE 8000

CMD ["uvicorn", "target_app:app", "--host", "0.0.0.0", "--port", "8000"]