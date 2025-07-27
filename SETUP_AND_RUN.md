# Zero-Day LLM Ensemble - Setup and Run Guide

## Complete Setup Instructions for 100% Functional System

### 1. **Initial Setup**

```bash
# Clone the repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. **Configure API Key**

```bash
# IMPORTANT: Use your API key from OpenRouter
export OPENROUTER_API_KEY="sk-or-v1-YOUR-KEY-HERE"
```

### 3. **Run with Real CVE Data**

#### Option A: Single CVE Analysis with Web Scraping (RECOMMENDED)

```bash
# Analyze a specific CVE (real example)
python run_analysis.py CVE-2023-23397 --verbose

# Analyze multiple CVEs
python run_analysis.py CVE-2023-23397 CVE-2021-44228 CVE-2024-3400 --verbose
```

#### Option B: Balanced Test with Real Data from CISA/NVD

```bash
# Test with 10 real zero-days and 10 regular CVEs
python run_complete_test.py --zero-days 10 --regular 10 --parallel

# Larger test (takes more time)
python run_complete_test.py --zero-days 20 --regular 20 --parallel
```

#### Option C: Batch Processing from File

```bash
# Create a file with CVEs to analyze
cat > my_cves.txt << EOF
CVE-2023-23397
CVE-2023-20198
CVE-2024-3400
CVE-2021-44228
CVE-2014-0160
CVE-2017-5638
EOF

# Run batch analysis
python run_analysis.py --file my_cves.txt --verbose
```

### 4. **Check Output**

Results will be in:
- `results/analysis_report_*.json` - Detailed report
- `results/analysis_summary_*.md` - Human-readable summary
- `reports/CVE-*_report_*.json` - Individual CVE reports

### 5. **Expected Output Example**

```
🚀 Zero-Day Detection System
============================================================
Analyzing 3 CVEs
Output directory: results
============================================================

[1/3] CVE-2023-23397
  📡 Collecting evidence for CVE-2023-23397...
  ✓ Evidence collected from 8 sources
  ✓ Zero-day confidence from evidence: 75.0%
  📌 Found in CISA Known Exploited Vulnerabilities
  📌 Associated with APT groups: LAZARUS
  
  🤖 Running LLM analysis...
  ✓ LLM prediction: 59.0%
  
  🎯 Final verdict: Zero-day
  Combined score: 69.0% (threshold: 55.0%)
  → Zero-day (confidence: 69.0%)
```

### 6. **Troubleshooting**

If you get errors:

#### API Key Error
```
Error: No auth credentials found
```
**Solution**: Make sure you set `OPENROUTER_API_KEY`

#### Rate Limit Error
```
Error: 429 Too Many Requests
```
**Solution**: Use fewer CVEs or add delays

#### Timeout Error
```
Command timed out
```
**Solution**: Use fewer CVEs for testing or disable `--parallel`

### 7. **Quick Functionality Test**

To verify everything works:

```bash
# Minimal test with 1 known CVE
python run_analysis.py CVE-2023-23397 -v

# If it works, you'll see:
# - Web scraping from 8 sources
# - LLM analysis from 5 agents
# - Final score and verdict
```

## IMPORTANT NOTES

- **USES REAL DATA**: System automatically downloads from CISA KEV and NVD
- **NO DEMO DATA**: All CVEs are real and verified
- **TIME**: Each CVE requires ~30-60 seconds for complete analysis
- **API LIMITS**: With free OpenRouter account, limit to 5-10 CVEs per test

The system is 100% functional with real data!