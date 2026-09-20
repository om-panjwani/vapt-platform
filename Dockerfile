FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    git \
    curl \
    wget \
    sqlite3 \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /vapt-platform

# Copy requirements and install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy the application code
COPY backend/ ./backend/
COPY database/ ./database/
COPY scanner/ ./scanner/
COPY vulnerability_engine/ ./vulnerability_engine/
COPY reports/ ./reports/
COPY frontend/ ./frontend/
COPY scripts/ ./scripts/

# Expose the FastAPI port
EXPOSE 8000

# Create necessary directories
RUN mkdir -p /vapt-platform/data /vapt-platform/logs /vapt-platform/reports/output

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    APP_SETTINGS=/vapt-platform/.env

# Start the application
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]