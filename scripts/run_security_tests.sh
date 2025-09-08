#!/bin/bash
# Odoo Security Test Suite Runner
# Usage: ./run_security_tests.sh [target_url] [--auto-remediate]

set -e

# Default values
TARGET_URL="http://localhost:8069"
AUTO_REMEDIATE=""
VERBOSE=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET_URL="$2"
            shift 2
            ;;
        --auto-remediate)
            AUTO_REMEDIATE="--auto-remediate"
            shift
            ;;
        --verbose|-v)
            VERBOSE="--verbose"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--target URL] [--auto-remediate] [--verbose]"
            echo "  --target URL        Target Odoo server (default: http://localhost:8069)"
            echo "  --auto-remediate    Automatically fix security issues where possible"
            echo "  --verbose          Enable verbose output"
            exit 0
            ;;
        *)
            TARGET_URL="$1"
            shift
            ;;
    esac
done

echo "Starting Odoo Security Assessment..."
echo "Target: $TARGET_URL"
echo "Auto-remediate: ${AUTO_REMEDIATE:-disabled}"
echo "----------------------------------------"

# Check if running as root for remediation
if [[ -n "$AUTO_REMEDIATE" && $EUID -ne 0 ]]; then
    echo "Warning: Auto-remediation requires root privileges"
    echo "Run with sudo for full remediation capabilities"
fi

# Install dependencies if needed
if ! python3 -c "import requests" 2>/dev/null; then
    echo "Installing required Python packages..."
    pip3 install requests psutil
fi

# Run the security test suite
python3 security_tests_odoo.py --target "$TARGET_URL" $AUTO_REMEDIATE $VERBOSE

echo "----------------------------------------"
echo "Security assessment complete!"
echo "Check security_test_odoo.log for detailed logs"
echo "Review the generated JSON report for full results"
