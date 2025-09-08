#!/bin/bash
# Odoo Security Test Suite Web Application Launcher
# Usage: ./run_webapp.sh

echo "Starting Odoo Security Test Suite Web Application..."
echo "======================================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is required but not installed."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Set environment variables
export FLASK_ENV=production
export FLASK_SECRET_KEY="change-this-secret-key-in-production"

# Create necessary directories
mkdir -p templates static logs

# Start the Flask application
echo "Starting web application on http://localhost:5000"
echo "Default credentials:"
echo "  Username: admin, Password: odoo_security_admin"
echo "  Username: devops, Password: devops_secure_2024"
echo ""
echo "IMPORTANT: Change these passwords in production!"
echo "======================================================="

python3 security_webapp_odoo.py
