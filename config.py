import os

class Config:
    """Application-wide configuration settings."""
    FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'your_super_secret_key_here_change_this_in_production_!!!')
    DATABASE_PATH = 'data/visto.db'
    LOG_DIR = 'data/logs'
    DATA_DIR = 'data' # <--- ADD THIS LINE IF IT'S MISSING
    FLASK_PORT = 5000
    DEBUG_MODE = True
    NMAP_PATH = '/usr/bin/nmap'

    # LLM Configuration
    LLM_API_URL = os.environ.get('LLM_API_URL', 'http://localhost:11434/v1/chat/completions')
    LLM_MODEL_NAME = os.environ.get('LLM_MODEL_NAME', 'phi3')
    LLM_API_KEY = os.environ.get('LLM_API_KEY', 'your_llm_api_key_here_change_this_in_production_!!!')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '[YOUR_SHODAN_API_KEY]]')

    # --- Scanning Control ---
    ALLOW_EXTERNAL_SCANNING = True
    INTERNAL_IP_RANGES = [
        "127.0.0.0/8",      # Loopback
        "10.0.0.0/8",       # Private A
        "172.16.0.0/12",    # Private B
        "192.168.0.0/16"    # Private C
        # Add any other internal IP ranges specific to your environment
    ]