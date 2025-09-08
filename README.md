# Odoo Security Test Suite

A comprehensive Flask-based web application for automated security testing of Odoo web servers.

## Features

- **Web-based Interface**: User-friendly dashboard for security testing
- **Automated Vulnerability Detection**: SQL injection, XSS, security headers, SSL/TLS
- **Auto-remediation**: Automatic fixing of certain security issues
- **Docker Support**: Easy deployment with Docker Compose
- **Detailed Reporting**: JSON reports with audit trails

## Quick Start with Docker

1. **Build and run the container:**
   \`\`\`bash
   chmod +x docker-run.sh
   ./docker-run.sh
   \`\`\`

2. **Access the webapp:**
   - URL: http://localhost:3011
   - Default credentials:
     - Username: `admin` Password: `odoo_security_admin`
     - Username: `devops` Password: `devops_secure_2024`

3. **Stop the container:**
   \`\`\`bash
   ./docker-stop.sh
   \`\`\`

## Manual Installation

1. **Install dependencies:**
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

2. **Run the application:**
   \`\`\`bash
   python security_webapp_odoo.py
   \`\`\`

## Environment Variables

- `FLASK_SECRET_KEY`: Secret key for Flask sessions
- `ADMIN_PASSWORD`: Password for admin user
- `DEVOPS_PASSWORD`: Password for devops user
- `FLASK_HOST`: Host to bind to (default: 0.0.0.0)
- `FLASK_PORT`: Port to bind to (default: 5000)

## Security Tests

- SQL Injection Detection
- Cross-Site Scripting (XSS)
- HTTP Security Headers
- SSL/TLS Configuration
- Authentication Security
- Information Disclosure

## Production Deployment

⚠️ **Important Security Notes:**
- Change default passwords before production use
- Use strong secret keys
- Run with proper SSL/TLS certificates
- Restrict network access appropriately

## File Structure

\`\`\`
├── security_webapp_odoo.py    # Main Flask application
├── scripts/
│   └── security_tests_odoo.py # Security test suite
├── templates/                 # HTML templates
├── logs/                     # Application logs
├── reports/                  # Security reports
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose setup
└── requirements.txt         # Python dependencies
