# 🚀 How to Use Zero-Day Detector

## Quick Start Guide

### 1. First Time Setup

```bash
# Clone the repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero_day-llm-ensemble

# Install dependencies
pip install -r requirements.txt

# Set your API key
export OPENROUTER_API_KEY="your-api-key-here"
```

### 2. Basic Usage - Detect a Single CVE

The simplest way to check if a CVE is a zero-day:

```bash
python zero_day_detector.py detect CVE-2024-3400
```

You'll see output like:
```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🎯 Zero-Day Vulnerability Detection System v3.12          ║
║     Multi-Agent LLM Ensemble with Context Enhancement         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

🔍 Analyzing CVE-2024-3400...
--------------------------------------------------

==================================================
🚨 ZERO-DAY VULNERABILITY DETECTED! 🚨
==================================================

📊 Detection Metrics:
   Detection Score: 68.0%
   Confidence: 75.2% (HIGH)
   Agent Agreement: 80.0%
   Analysis Time: 15.3s

🔍 Evidence Summary:
   Sources Checked: 21
   CISA KEV Listed: Yes
   Exploitation Evidence: Found
   Honeypot Activity: Detected

📌 Key Indicators:
   • Listed in CISA KEV
   • Rapid KEV addition (<7 days)
   • Exploitation before patch
   • Honeypot detections: 3

💾 Report saved to: reports/CVE-2024-3400_report_20250804_123456.json
```

### 3. Check System Status

Before running detection, check if everything is configured:

```bash
python zero_day_detector.py status
```

This shows:
- ✅ Configuration status
- 🎯 Current detection thresholds
- 💾 Cache status
- 🔑 API key configuration

### 4. Test with Multiple CVEs

To evaluate the system's performance:

```bash
# Test with 20 CVEs (10 zero-days + 10 regular)
python zero_day_detector.py test --zero-days 10 --regular 10
```

### 5. Verify Data Collection

To see what data is being collected without running detection:

```bash
python zero_day_detector.py verify CVE-2024-3400
```

This shows all the sources being scraped and data points collected.

## Understanding the Results

### Detection Score
- **> 50%**: Likely a zero-day
- **< 50%**: Likely a regular vulnerability
- The threshold adjusts based on confidence level

### Confidence Levels
- **HIGH (≥80%)**: Very confident in the result
- **MEDIUM (60-80%)**: Reasonably confident
- **LOW (40-60%)**: Less certain, may need human review
- **VERY LOW (<40%)**: Uncertain, requires verification

### Key Indicators
The system looks for:
- CISA KEV listing
- Exploitation timeline
- APT group associations
- Honeypot detections
- Community discussions
- Patch urgency signals

## Advanced Usage

### Verbose Mode
For detailed analysis showing all evidence:
```bash
python zero_day_detector.py detect CVE-2024-3400 -v
```

### Evidence Only Mode
To see just the data collection without LLM analysis:
```bash
python zero_day_detector.py detect CVE-2024-3400 -e
```

### Batch Testing
For testing many CVEs from a file:
```bash
python scripts/universal_tester.py --zero-days 50 --regular 50 --parallel
```

### Custom Datasets
Place your CVE lists in `data/` directory as JSON files.

## Common CVEs for Testing

### Known Zero-Days
- `CVE-2024-3400` - Palo Alto PAN-OS
- `CVE-2021-44228` - Log4j (Log4Shell)
- `CVE-2023-20198` - Cisco IOS XE
- `CVE-2022-30190` - Microsoft MSDT (Follina)

### Regular Vulnerabilities
- `CVE-2021-3156` - Sudo Baron Samedit
- `CVE-2024-38063` - Windows TCP/IP
- `CVE-2019-0708` - Windows RDP (BlueKeep)

## Troubleshooting

### API Key Issues
```
❌ OpenRouter API key: Not set
```
Solution: `export OPENROUTER_API_KEY='your-key'`

### Rate Limiting
If you see many 429 errors, the system is being rate limited. Wait a few minutes or use cached results.

### No Results
Some CVEs may not have enough public information. Try well-known CVEs first.

## Tips for Best Results

1. **Use Recent CVEs**: Better data availability for CVEs from 2020 onwards
2. **Check Status First**: Run `status` command to ensure proper setup
3. **Use Cache**: The system caches results for 7 days to save API calls
4. **Parallel Testing**: Use `--parallel` flag for faster batch testing
5. **Save Reports**: Reports are automatically saved in `reports/` directory

## Need Help?

- Check `python zero_day_detector.py --help`
- Review examples in this guide
- Check the logs in `logs/` directory for debugging
- Submit issues on GitHub