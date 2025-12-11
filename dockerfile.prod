FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# -------------------------------------------------------
# Install build dependencies
# -------------------------------------------------------
FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --user -r requirements.txt


# -------------------------------------------------------
# Final production image
# -------------------------------------------------------
FROM base AS production

# Add non-root user for security
RUN useradd -m appuser

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local

# Ensure Python finds the installed packages
ENV PATH=/root/.local/bin:$PATH

# Copy application source code
COPY . .

# Change ownership
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Production server (Gunicorn + Uvicorn workers)
CMD ["gunicorn", "main:app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000"]
