#!/bin/bash

# Stop Odoo Security Suite Docker container

echo "🛑 Stopping Odoo Security Test Suite..."
docker-compose down

echo "✅ Container stopped successfully!"
echo ""
echo "📋 To start again, run: ./docker-run.sh"
