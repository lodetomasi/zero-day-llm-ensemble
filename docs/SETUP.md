# Setup Guide

This guide will help you set up the Zero-Day LLM Ensemble system.

## 📋 Prerequisites

- Python 3.8 or higher
- Git
- 8GB+ RAM recommended
- Internet connection for API calls

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API Keys

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your OpenRouter API key:

```
OPENROUTER_API_KEY=your-api-key-here
```

Get your API key from: https://openrouter.ai/keys

## 🧪 Verify Installation

Test the system with cached results (no API calls):

```bash
python scripts/quick_test.py
```

Test connectivity to LLM models:

```bash
python -c "from src.ensemble.multi_agent import MultiAgentSystem; MultiAgentSystem().test_connectivity()"
```

## 📁 Directory Structure

After setup, your directory should look like:

```
zero-day-llm-ensemble/
├── .env              # Your API keys (git-ignored)
├── venv/             # Virtual environment (git-ignored)
├── src/              # Source code
├── scripts/          # Executable scripts
├── config/           # Configuration files
├── data/             # Datasets and cache
└── results/          # Experiment results
```

## ⚠️ Common Issues

### API Key Error
- Ensure `.env` file exists and contains valid `OPENROUTER_API_KEY`
- Check that the key has sufficient credits

### Import Errors
- Make sure you're in the virtual environment
- Run from the project root directory

### Rate Limiting
- The system includes rate limiting between API calls
- For large-scale tests, expect ~1-2 seconds between CVE analyses

## 🔒 Security Notes

- Never commit `.env` file to version control
- API keys are automatically excluded via `.gitignore`
- All web scraping respects robots.txt and rate limits

## 📞 Support

For issues, please check:
1. [Troubleshooting Guide](../README.md#troubleshooting)
2. [GitHub Issues](https://github.com/lodetomasi/zero-day-llm-ensemble/issues)
3. Contact: lorenzo.detomasi@graduate.univaq.it