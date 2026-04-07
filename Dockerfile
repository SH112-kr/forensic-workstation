FROM python:3.12-slim

# System deps + Node.js
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg wget unzip jq && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Backend dependencies (core + all optional)
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt \
    volatility3 yara-python regipy pyhidra pyshark

# JDK 21 (required for Ghidra)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ghidra (auto-download latest release)
RUN GHIDRA_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
    | jq -r '.assets[] | select(.name | test("ghidra.*\\.zip$")) | select(.name | test("src") | not) | .browser_download_url' \
    | head -1) && \
    echo "Downloading Ghidra: $GHIDRA_URL" && \
    wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip && \
    unzip -q /tmp/ghidra.zip -d /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    GHIDRA_DIR=$(ls -d /opt/ghidra/ghidra_* | head -1) && \
    echo "FORENSIC_GHIDRA_INSTALL_DIR=$GHIDRA_DIR" >> /etc/environment
ENV FORENSIC_GHIDRA_INSTALL_DIR=/opt/ghidra

# Frontend build
COPY frontend/package.json frontend/package-lock.json frontend/
RUN cd frontend && npm ci --silent

COPY frontend/ frontend/
RUN cd frontend && npm run build

# Backend code
COPY backend/ backend/
COPY CLAUDE.md .

# Mount points
RUN mkdir -p /evidence /app/projects

EXPOSE 8001
ENV PORT=8001
ENV DOCKER=1

CMD ["sh", "-c", "FORENSIC_GHIDRA_INSTALL_DIR=$(ls -d /opt/ghidra/ghidra_* 2>/dev/null | head -1) exec python backend/main.py"]
