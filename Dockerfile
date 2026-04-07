FROM python:3.12-slim

# Install Node.js for frontend build
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Backend dependencies
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Frontend build
COPY frontend/package.json frontend/package-lock.json frontend/
RUN cd frontend && npm ci --silent

COPY frontend/ frontend/
RUN cd frontend && npm run build

# Backend code
COPY backend/ backend/
COPY CLAUDE.md .

# Evidence mount point
RUN mkdir -p /evidence

EXPOSE 8001

ENV PORT=8001

CMD ["python", "backend/main.py"]
