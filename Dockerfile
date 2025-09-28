# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml requirements.txt requirements-optional.txt ./
COPY src/ src/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-optional.txt

# Create reports directory
RUN mkdir -p reports

# Expose port for Streamlit UI
EXPOSE 8501

# Create a non-root user
RUN useradd --create-home --shell /bin/bash scanner
USER scanner
WORKDIR /home/scanner/app

# Copy project files to user directory
COPY --chown=scanner:scanner . .

# Set entrypoint
ENTRYPOINT ["python", "-m", "boltvuln.cli"]