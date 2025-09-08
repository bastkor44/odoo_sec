#!/bin/bash

# Odoo Security Suite Docker Runner
# This script builds and runs the Odoo Security Test Suite webapp

echo "🔒 Odoo Security Test Suite - Docker Setup"
echo "=========================================="

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs reports

# Set proper permissions
chmod 755 logs reports

# Build and start the container
echo "🐳 Building and starting Docker container..."
docker-compose up --build -d

# Wait for container to be ready
echo "⏳ Waiting for application to start..."
sleep 10

# Check if container is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Container is running successfully!"
    echo ""
    echo "🌐 Access the webapp at: http://localhost:3011"
    echo ""
    echo "🔑 Default credentials:"
    echo "   Username: admin    Password: odoo_security_admin"
    echo "   Username: devops   Password: devops_secure_2024"
    echo ""
    echo "⚠️  IMPORTANT: Change default passwords in production!"
    echo ""
    echo "📋 Useful commands:"
    echo "   View logs:     docker-compose logs -f"
    echo "   Stop service:  docker-compose down"
    echo "   Restart:       docker-compose restart"
else
    echo "❌ Container failed to start. Check logs:"
    docker-compose logs
fi
