"""
Global configuration settings for Zero-Day Detection System
"""
import os
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"
LOGS_DIR = PROJECT_ROOT / "logs"

# API Configuration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# External API URLs
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Model Configuration
AGENT_MODELS = {
    "ForensicAnalyst": "mistralai/mixtral-8x22b-instruct",
    "PatternDetector": "anthropic/claude-opus-4", 
    "TemporalAnalyst": "meta-llama/llama-3.3-70b-instruct",
    "AttributionExpert": "deepseek/deepseek-r1-0528",
    "MetaAnalyst": "google/gemini-2.5-pro"
}

# Experiment Configuration
RANDOM_SEED = 42
MAX_RETRIES = 3
RETRY_DELAY = 2.0
RATE_LIMIT_DELAY = 0.5
REQUEST_TIMEOUT = 30

# Data Configuration
MAX_ZERO_DAYS = 100
MAX_REGULAR_CVES = 100
TEST_SPLIT_RATIO = 0.3
VALIDATION_SPLIT_RATIO = 0.1

# Debug Configuration
DEBUG_MODE = False
VERBOSE_LOGGING = False
SAVE_INTERMEDIATE_RESULTS = False

# Statistical Testing
BOOTSTRAP_ITERATIONS = 1000
CONFIDENCE_LEVEL = 0.95
MCNEMAR_SIGNIFICANCE_LEVEL = 0.05

# Visualization
FIGURE_DPI = 300
FIGURE_SIZE = (12, 8)
COLOR_PALETTE = "Set2"