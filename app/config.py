"""
Configuration and utilities for SHODAN VulnScopeX Live Web App
"""

import os
import emoji
from datetime import datetime

# Database
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'scan_results', 'vulnerabilities.db')

# API Configuration
API_VERSION = "v2"
API_TIMEOUT = 30

# Flask Configuration
FLASK_CONFIG = {
    'TITLE': 'SHODAN VulnScopeX Live',
    'VERSION': '2.0',
    'DEBUG': False,
    'SECRET_KEY': 'shodan-vulnscope-2024',
    'JSONIFY_PRETTYPRINT_REGULAR': True
}

# SHODAN Configuration
SHODAN_CONFIG = {
    'API_KEY': os.getenv('SHODAN_API_KEY', 'test_api_key_demo_mode'),  # TEST MODE - Replace with your actual SHODAN API key
    'DEFAULT_LIMIT': 50,
    'MAX_LIMIT': 1000,
    'TIMEOUT': 10
}

# App Features
FEATURES = {
    'REAL_TIME_UPDATES': True,
    'LIVE_CRUD': True,
    'DARK_MODE': True,
    'ADVANCED_FILTERING': True,
    'BATCH_OPERATIONS': True,
    'EXPORT': True,
    'WEBHOOKS': False,
}

# Logging
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '[%(asctime)s] %(levelname)s: %(message)s',
    'file': 'app.log'
}
