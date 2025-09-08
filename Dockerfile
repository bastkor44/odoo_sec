FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security BEFORE copying files
RUN useradd -m -u 1000 appuser

# Copy application files
COPY . .

RUN mkdir -p templates static reports && \
    chmod -R 755 templates static reports && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Set environment variables
ENV FLASK_APP=security_webapp_odoo.py
ENV FLASK_ENV=production
ENV FLASK_SECRET_KEY=odoo-security-suite-production-key-change-me

# Expose port 5000 (Flask default)
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

# Run the application
CMD ["python", "security_webapp_odoo.py"]
