# 🚀 Quick Start Guide

Get started with Zero-Day Detection in 5 minutes!

## 1. Prerequisites

```bash
# Python 3.8+ required
python --version

# Install dependencies
pip install -r requirements.txt
```

## 2. Set API Key

```bash
# Get your key from https://openrouter.ai/
export OPENROUTER_API_KEY="your-api-key-here"
```

## 3. Your First Detection

```bash
# Detect a known zero-day
python zero_day_detector.py detect CVE-2024-3400

# Expected output:
# 🎯 DETECTION RESULT: ZERO-DAY DETECTED
# 📊 Detection Score: 85.3%
# 🔍 Key Indicators: CISA KEV listing, APT activity...
```

## 4. Test the System

```bash
# Quick test with 10 CVEs
python zero_day_detector.py test --zero-days 5 --regular 5

# Expected: ~80% accuracy
```

## 5. Common Commands

```bash
# Check system status
python zero_day_detector.py status

# Verify data collection works
python zero_day_detector.py verify CVE-2024-3400

# See help
python zero_day_detector.py --help
```

## Next Steps

- Read [HOW_TO_USE.md](HOW_TO_USE.md) for detailed usage
- See [DATASET_MANAGEMENT.md](DATASET_MANAGEMENT.md) to expand datasets
- Check [ARCHITECTURE.md](ARCHITECTURE.md) to understand the system

## Troubleshooting

**"No API key found"**
```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
```

**"Rate limit exceeded"**
- Wait a few seconds between requests
- Use cached results when available

**"Import error"**
```bash
pip install -r requirements.txt
```

## Example CVEs to Try

**Zero-Days:**
- CVE-2024-3400 (Palo Alto PAN-OS)
- CVE-2021-44228 (Log4Shell)
- CVE-2023-20198 (Cisco IOS XE)

**Regular CVEs:**
- CVE-2024-38063 (Windows TCP/IP)
- CVE-2019-0708 (BlueKeep)
- CVE-2021-3156 (Sudo Baron Samedit)