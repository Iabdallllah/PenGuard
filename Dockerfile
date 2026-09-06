FROM python:3.11-slim

WORKDIR /app

# System deps for weasyprint + chroma
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Chroma persistence
RUN mkdir -p /app/chroma_db

EXPOSE 8000
EXPOSE 8001

# Render/Vercel provide $PORT (single port). We run both servers via start.sh
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
