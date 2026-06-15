# ─────────────────────────────────────────────────────────────
# TokenShield / NeoVault — Flask Application Container
# ─────────────────────────────────────────────────────────────
# Build:   docker build -t tokenshield .
# Run:     docker-compose up
# ─────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Metadata
LABEL maintainer="TokenShield Project"
LABEL description="NeoVault Banking + TokenShield Security Engine"

# System deps (gcc needed for some pip packages, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        curl \
        libffi-dev \
        python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Install Python dependencies first (layer-cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create the instance folder for SQLite
RUN mkdir -p /app/instance

# Expose Flask port
EXPOSE 5001

# Health check — Docker and GNS3 use this to know the container is ready
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

# Default environment (overridden in docker-compose.yml)
ENV FLASK_ENV=production \
    FLASK_DEBUG=0 \
    DATABASE_URL=sqlite:////app/instance/tokenshield.db \
    SECRET_KEY=change-me-in-production \
    JWT_SECRET_KEY=jwt-change-me-in-production

# Initialise database then start Flask
CMD ["python", "run.py"]