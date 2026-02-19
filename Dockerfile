# ---- Build stage: compile dependencies that need gcc ----
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-prod.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements-prod.txt

# ---- Final stage: slim runtime without gcc ----
FROM python:3.11-slim

WORKDIR /app

# Copy only the installed packages from the build stage
COPY --from=builder /install /usr/local

# Copy application code
COPY main.py app.py models.py routes.py ./
COPY services/ ./services/
COPY utilities/ ./utilities/

# Create a non-root user for security
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port (Cloud Run will set the PORT environment variable)
EXPOSE 8080

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Command to run the application
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
