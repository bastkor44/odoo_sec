#!/usr/bin/env python3
"""
Odoo Security Test Suite Web Application
========================================

A Flask-based web interface for the Odoo Security Test Suite.
Provides a user-friendly interface for DevOps engineers to configure,
run, and view results of security tests for Odoo web servers.

Author: AI Security Engineer
Version: 1.0
Dependencies: flask, requests, werkzeug

Usage:
    python3 security_webapp_odoo.py
    Access via browser: http://localhost:5000
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import unittest
from io import StringIO

try:
    from scripts.security_tests_odoo import OdooSecurityTestSuite, OdooSecurityConfig
except ImportError:
    # Fallback for Docker environment
    sys.path.append('/app/scripts')
    from security_tests_odoo import OdooSecurityTestSuite, OdooSecurityConfig

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'odoo-security-suite-key-change-in-production')

def ensure_directories():
    """Ensure all necessary directories exist with proper permissions"""
    directories = ['templates', 'static', 'logs', 'reports']
    for directory in directories:
        dir_path = Path(directory)
        dir_path.mkdir(exist_ok=True, mode=0o755)
        try:
            os.chmod(str(dir_path), 0o755)
        except PermissionError:
            pass  # Ignore permission errors in restricted environments

def setup_logging():
    """Setup logging with fallback to console-only if file creation fails"""
    handlers = []
    
    # Always add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    handlers.append(console_handler)
    
    # Try to add file handler, fallback to console-only if it fails
    try:
        log_file = 'logs/security_webapp_odoo.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        handlers.append(file_handler)
    except (PermissionError, OSError) as e:
        print(f"Warning: Could not create log file, using console logging only: {e}")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

ensure_directories()
setup_logging()
logger = logging.getLogger(__name__)

def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User authentication endpoint"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS and check_password_hash(USERS[username], password):
            session['user'] = username
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for user: {username}")
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout endpoint"""
    user = session.get('user', 'unknown')
    session.pop('user', None)
    logger.info(f"User {user} logged out")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    """Main dashboard with test configuration and results"""
    return render_template('dashboard.html', 
                         test_results=test_results, 
                         test_status=test_status)

@app.route('/configure', methods=['GET', 'POST'])
@login_required
def configure():
    """Test configuration page"""
    if request.method == 'POST':
        config = {
            'base_url': request.form.get('base_url', 'http://example.com').strip(),
            'auto_remediate': 'auto_remediate' in request.form,
            'test_categories': request.form.getlist('test_categories')
        }
        
        # Validate URL format
        if not config['base_url'].startswith(('http://', 'https://')):
            flash('Please enter a valid URL starting with http:// or https://', 'error')
            return render_template('configure.html')
        
        # Store configuration in session
        session['test_config'] = config
        logger.info(f"Test configuration updated by {session['user']}: {config}")
        flash('Configuration saved successfully', 'success')
        return redirect(url_for('dashboard'))
    
    # Get current configuration
    current_config = session.get('test_config', {
        'base_url': 'http://example.com',
        'auto_remediate': False,
        'test_categories': ['all']
    })
    
    return render_template('configure.html', config=current_config)

@app.route('/run_tests', methods=['POST'])
@login_required
def run_tests():
    """Start security tests execution"""
    global test_status, test_results
    
    if test_status['running']:
        return jsonify({'error': 'Tests are already running'}), 400
    
    config = session.get('test_config')
    if not config:
        return jsonify({'error': 'No configuration found. Please configure tests first.'}), 400
    
    # Start tests in background thread
    test_thread = threading.Thread(target=execute_security_tests, args=(config,))
    test_thread.daemon = True
    test_thread.start()
    
    logger.info(f"Security tests started by {session['user']} for {config['base_url']}")
    return jsonify({'message': 'Tests started successfully'})

@app.route('/test_status')
@login_required
def get_test_status():
    """Get current test execution status"""
    return jsonify(test_status)

@app.route('/test_results')
@login_required
def get_test_results():
    """Get latest test results"""
    return jsonify(test_results)

@app.route('/download_report')
@login_required
def download_report():
    """Download detailed security report"""
    if not test_results:
        flash('No test results available', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate detailed report
    report = {
        'timestamp': datetime.now().isoformat(),
        'generated_by': session['user'],
        'configuration': session.get('test_config', {}),
        'results': test_results,
        'summary': generate_summary(test_results)
    }
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f'reports/odoo_security_report_{timestamp}.json'
    
    try:
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Security report downloaded by {session['user']}: {report_filename}")
        flash(f'Report saved as {report_filename}', 'success')
    except (PermissionError, OSError) as e:
        logger.error(f"Failed to save report: {e}")
        flash('Failed to save report file. Check permissions.', 'error')
    
    return redirect(url_for('dashboard'))

def execute_security_tests(config):
    """Execute security tests in background thread"""
    global test_status, test_results
    
    test_status['running'] = True
    test_status['progress'] = 0
    test_status['current_test'] = 'Initializing...'
    
    try:
        # Set up test suite with configuration
        OdooSecurityTestSuite.target_url = config['base_url']
        
        # Create custom test runner to capture results
        test_suite = unittest.TestLoader().loadTestsFromTestCase(OdooSecurityTestSuite)
        
        # Run tests with custom result handler
        result_handler = CustomTestResult()
        runner = unittest.TextTestRunner(stream=StringIO(), resultclass=lambda: result_handler)
        
        # Execute tests
        test_status['current_test'] = 'Running security tests...'
        test_status['progress'] = 20
        
        test_result = runner.run(test_suite)
        
        # Collect results from test instances
        test_status['current_test'] = 'Collecting results...'
        test_status['progress'] = 80
        
        # Get results from the test suite
        test_instance = OdooSecurityTestSuite()
        test_instance.config = OdooSecurityConfig(config['base_url'])
        
        # Run each test method individually to collect results
        collected_results = {}
        test_methods = [
            ('test_01_server_information_disclosure', 'Information Disclosure'),
            ('test_02_sql_injection_detection', 'SQL Injection'),
            ('test_03_xss_detection', 'XSS Vulnerabilities'),
            ('test_04_insecure_http_headers', 'HTTP Headers'),
            ('test_05_ssl_tls_configuration', 'SSL/TLS Configuration'),
            ('test_06_authentication_security', 'Authentication Security')
        ]
        
        for method_name, display_name in test_methods:
            test_status['current_test'] = f'Running {display_name}...'
            try:
                method = getattr(test_instance, method_name)
                method()
                if hasattr(test_instance, 'test_results'):
                    collected_results.update(test_instance.test_results)
            except Exception as e:
                logger.error(f"Error running {method_name}: {e}")
                collected_results[method_name] = {'error': str(e)}
        
        # Perform auto-remediation if requested
        remediation_results = []
        if config.get('auto_remediate', False):
            test_status['current_test'] = 'Performing auto-remediation...'
            test_status['progress'] = 90
            try:
                test_instance.remediate_http_headers()
                if hasattr(test_instance, 'remediation_actions'):
                    remediation_results = test_instance.remediation_actions
            except Exception as e:
                logger.error(f"Auto-remediation failed: {e}")
                remediation_results.append({
                    'action': 'Auto-remediation',
                    'status': 'Failed',
                    'error': str(e)
                })
        
        # Store final results
        test_results.update({
            'timestamp': datetime.now().isoformat(),
            'target_url': config['base_url'],
            'vulnerabilities': collected_results,
            'remediation_actions': remediation_results,
            'summary': generate_summary(collected_results),
            'configuration': config
        })
        
        test_status['current_test'] = 'Tests completed'
        test_status['progress'] = 100
        
        logger.info(f"Security tests completed for {config['base_url']}")
        
    except Exception as e:
        logger.error(f"Security tests failed: {e}")
        test_results['error'] = str(e)
        test_status['current_test'] = f'Tests failed: {str(e)}'
    
    finally:
        test_status['running'] = False

class CustomTestResult(unittest.TestResult):
    """Custom test result handler to capture detailed results"""
    
    def __init__(self):
        super().__init__()
        self.test_results = {}
    
    def startTest(self, test):
        super().startTest(test)
        global test_status
        test_status['current_test'] = f'Running {test._testMethodName}...'
    
    def addSuccess(self, test):
        super().addSuccess(test)
        self.test_results[test._testMethodName] = 'passed'
    
    def addError(self, test, err):
        super().addError(test, err)
        self.test_results[test._testMethodName] = f'error: {err[1]}'
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.test_results[test._testMethodName] = f'failed: {err[1]}'

def generate_summary(results):
    """Generate summary statistics from test results"""
    summary = {
        'total_vulnerabilities': 0,
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'categories': {}
    }
    
    for category, issues in results.items():
        if isinstance(issues, list):
            summary['categories'][category] = len(issues)
            summary['total_vulnerabilities'] += len(issues)
            
            for issue in issues:
                if isinstance(issue, dict):
                    severity = issue.get('severity', 'Unknown').lower()
                    if severity in summary:
                        summary[severity] += 1
    
    return summary

def create_template_files():
    """Create HTML template files"""
    
    # Base template
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Odoo Security Test Suite{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .vulnerability-critical { border-left: 4px solid #dc3545; }
        .vulnerability-high { border-left: 4px solid #fd7e14; }
        .vulnerability-medium { border-left: 4px solid #ffc107; }
        .vulnerability-low { border-left: 4px solid #20c997; }
        .test-running { animation: pulse 2s infinite; }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt"></i> Odoo Security Suite
            </a>
            {% if session.user %}
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, {{ session.user }}</span>
                <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
            </div>
            {% endif %}
        </div>
    </nav>
    
    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''

    # Login template
    login_template = '''{% extends "base.html" %}
{% block title %}Login - Odoo Security Suite{% endblock %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h4><i class="fas fa-lock"></i> Secure Access Required</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                </form>
                <div class="mt-3">
                    <small class="text-muted">
                        Default credentials: admin/odoo_security_admin or devops/devops_secure_2024<br>
                        <strong>Change these passwords in production!</strong>
                    </small>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    # Dashboard template
    dashboard_template = '''{% extends "base.html" %}
{% block content %}
<div class="row">
    <div class="col-md-12">
        <h2><i class="fas fa-tachometer-alt"></i> Security Dashboard</h2>
        
        <!-- Test Status -->
        <div class="card mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5><i class="fas fa-play-circle"></i> Test Execution</h5>
                <div>
                    <a href="{{ url_for('configure') }}" class="btn btn-secondary btn-sm">
                        <i class="fas fa-cog"></i> Configure
                    </a>
                    <button id="runTestsBtn" class="btn btn-primary btn-sm" onclick="runTests()">
                        <i class="fas fa-play"></i> Run Tests
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div id="testStatus">
                    {% if test_status.running %}
                        <div class="test-running">
                            <div class="progress mb-2">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     style="width: {{ test_status.progress }}%"></div>
                            </div>
                            <p><i class="fas fa-spinner fa-spin"></i> {{ test_status.current_test }}</p>
                        </div>
                    {% else %}
                        <p><i class="fas fa-check-circle text-success"></i> Ready to run security tests</p>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <!-- Test Results -->
        {% if test_results %}
        <div class="card mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5><i class="fas fa-chart-bar"></i> Test Results Summary</h5>
                <a href="{{ url_for('download_report') }}" class="btn btn-success btn-sm">
                    <i class="fas fa-download"></i> Download Report
                </a>
            </div>
            <div class="card-body">
                {% if test_results.summary %}
                <div class="row text-center mb-3">
                    <div class="col-md-2">
                        <h4 class="text-danger">{{ test_results.summary.critical }}</h4>
                        <small>Critical</small>
                    </div>
                    <div class="col-md-2">
                        <h4 class="text-warning">{{ test_results.summary.high }}</h4>
                        <small>High</small>
                    </div>
                    <div class="col-md-2">
                        <h4 class="text-info">{{ test_results.summary.medium }}</h4>
                        <small>Medium</small>
                    </div>
                    <div class="col-md-2">
                        <h4 class="text-success">{{ test_results.summary.low }}</h4>
                        <small>Low</small>
                    </div>
                    <div class="col-md-4">
                        <h4>{{ test_results.summary.total_vulnerabilities }}</h4>
                        <small>Total Issues</small>
                    </div>
                </div>
                {% endif %}
                
                <p><strong>Target:</strong> {{ test_results.target_url }}</p>
                <p><strong>Tested:</strong> {{ test_results.timestamp }}</p>
            </div>
        </div>
        {% endif %}
    </div>
</div>

<script>
function runTests() {
    const btn = document.getElementById('runTestsBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
    
    fetch('/run_tests', {method: 'POST'})
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-play"></i> Run Tests';
            } else {
                pollTestStatus();
            }
        })
        .catch(error => {
            alert('Error starting tests: ' + error);
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-play"></i> Run Tests';
        });
}

function pollTestStatus() {
    const statusDiv = document.getElementById('testStatus');
    const btn = document.getElementById('runTestsBtn');
    
    const poll = setInterval(() => {
        fetch('/test_status')
            .then(response => response.json())
            .then(status => {
                if (status.running) {
                    statusDiv.innerHTML = `
                        <div class="test-running">
                            <div class="progress mb-2">
                                <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                     style="width: ${status.progress}%"></div>
                            </div>
                            <p><i class="fas fa-spinner fa-spin"></i> ${status.current_test}</p>
                        </div>
                    `;
                } else {
                    clearInterval(poll);
                    statusDiv.innerHTML = '<p><i class="fas fa-check-circle text-success"></i> Tests completed! Refreshing page...</p>';
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fas fa-play"></i> Run Tests';
                    setTimeout(() => location.reload(), 2000);
                }
            })
            .catch(error => {
                clearInterval(poll);
                statusDiv.innerHTML = '<p><i class="fas fa-exclamation-triangle text-danger"></i> Error polling status</p>';
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-play"></i> Run Tests';
            });
    }, 2000);
}
</script>
{% endblock %}'''

    # Configuration template
    configure_template = '''{% extends "base.html" %}
{% block title %}Configure Tests - Odoo Security Suite{% endblock %}
{% block content %}
<div class="row">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h4><i class="fas fa-cog"></i> Test Configuration</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="base_url" class="form-label">Target Odoo Server URL</label>
                        <input type="url" class="form-control" id="base_url" name="base_url" 
                               value="{{ config.base_url }}" required
                               placeholder="https://your-odoo-server.com">
                        <div class="form-text">Enter the base URL of your Odoo server</div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="auto_remediate" name="auto_remediate" 
                                   {{ 'checked' if config.auto_remediate else '' }}>
                            <label class="form-check-label" for="auto_remediate">
                                <strong>Enable Automatic Remediation</strong>
                            </label>
                            <div class="form-text text-warning">
                                <i class="fas fa-exclamation-triangle"></i> 
                                This will automatically fix certain security issues by modifying configurations.
                                Backups will be created before any changes.
                            </div>
                        </div>
                    </div>
                    
                    <div class="d-grid gap-2 d-md-flex justify-content-md-end">
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancel</a>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save"></i> Save Configuration
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''

    templates = [
        ('templates/base.html', base_template),
        ('templates/login.html', login_template),
        ('templates/dashboard.html', dashboard_template),
        ('templates/configure.html', configure_template)
    ]
    
    for filename, content in templates:
        try:
            with open(filename, 'w') as f:
                f.write(content)
        except (PermissionError, OSError) as e:
            print(f"Warning: Could not create template file {filename}: {e}")

if __name__ == '__main__':
    logger.info("Starting Odoo Security Test Suite Web Application")
    logger.info("Default credentials: admin/odoo_security_admin or devops/devops_secure_2024")
    logger.warning("CHANGE DEFAULT PASSWORDS IN PRODUCTION!")
    
    create_template_files()
    
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    app.run(host=host, port=port, debug=debug)
