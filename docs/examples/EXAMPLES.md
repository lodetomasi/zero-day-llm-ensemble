# Real Examples and Usage

## 1. Detecting a Single CVE

### Example: Log4j (CVE-2021-44228)
```bash
$ python zero_day_detector.py detect CVE-2021-44228

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
║     Multi-Agent LLM Ensemble with Context Enhancement         ║
╚═══════════════════════════════════════════════════════════════╝

🔍 Analyzing CVE-2021-44228...
--------------------------------------------------

============================================================
🎯 DETECTION RESULT: ZERO-DAY DETECTED
============================================================

📊 Detection Score: 79.5%
   Confidence: 66.0% (MEDIUM)
   Agent Agreement: 80.0%
   Analysis Time: 12.7s

🔍 Evidence Summary:
   Sources Checked: 21
   CISA KEV Listed: Yes
   Exploitation Evidence: Found
   Honeypot Activity: Detected

📌 Key Indicators:
   • Listed in CISA KEV
   • Rapid KEV addition (<7 days)
   • Exploitation before patch
   • Honeypot detections: 2
   • APT association (1 groups)
```

### Example: Regular CVE (CVE-2024-38068)
```bash
$ python zero_day_detector.py detect CVE-2024-38068

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
╚═══════════════════════════════════════════════════════════════╝

🔍 Analyzing CVE-2024-38068...
--------------------------------------------------

============================================================
✅ Regular Vulnerability (Not a Zero-Day)
============================================================

📊 Detection Score: 26.5%
   Confidence: 75.0% (MEDIUM)
   Agent Agreement: 60.0%
   Analysis Time: 10.2s

🔍 Evidence Summary:
   Sources Checked: 21
   CISA KEV Listed: No
   Exploitation Evidence: Not found
   Honeypot Activity: None

🔍 Key Indicators: None

💭 Reasoning: Not detected as zero-day due to: no government alerts
```

## 2. Testing System Performance

```bash
$ python zero_day_detector.py test --zero-days 3 --regular 3

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
╚═══════════════════════════════════════════════════════════════╝

🧪 Testing with 3 zero-days and 3 regular CVEs...
--------------------------------------------------
Selected 6 CVEs for testing

🚀 Running tests in parallel with 4 workers...

[Progress bars and real-time results]

============================================================
📊 TEST RESULTS SUMMARY
============================================================

🎯 Performance Metrics:
  Accuracy: 66.7%
  Precision: 66.7%
  Recall: 66.7%
  F1 Score: 0.667

📈 Confusion Matrix:
  True Positives: 2
  True Negatives: 2
  False Positives: 1
  False Negatives: 1

⚡ Performance:
  Total time: 62.3s
  Avg per CVE: 10.4s
  Cache hit rate: 0.0%

💭 Confidence Analysis:
  Average: 63.3%
  Range: 48.0% - 79.3%
```

## 3. Downloading and Balancing CVEs

```bash
$ python zero_day_detector.py download --total 50

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
╚═══════════════════════════════════════════════════════════════╝

📥 Downloading and preparing 50 CVEs...
--------------------------------------------------

🔍 Step 1: Fetching CVEs from multiple sources...
   • CISA KEV (all known zero-days)
   • NVD recent vulnerabilities
   • Historical CVEs
   • Low/medium severity CVEs (likely regular)

📊 Downloading zero-days and recent CVEs...
📊 Downloading additional regular CVEs...

⚖️  Step 2: Creating balanced dataset with 50 CVEs...
   • Target: 25 zero-days + 25 regular CVEs

✅ Success! Balanced dataset created:
   📁 File: data/balanced_dataset_50.json
   📊 Contents: 25 zero-days + 25 regular CVEs

💡 To test with this dataset:
   python zero_day_detector.py test --zero-days 25 --regular 25

📊 Available Datasets:
   • balanced_dataset_50.json: 50 CVEs (25 zero-days, 25 regular)
   • balanced_dataset_100.json: 100 CVEs (50 zero-days, 50 regular)
   • verified_dataset.json: 60 CVEs (30 zero-days, 30 regular)
   • full_dataset.json: 1548 CVEs (1410 zero-days, 138 regular)
```

## 4. Verifying Data Collection

```bash
$ python zero_day_detector.py verify CVE-2024-3400

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
╚═══════════════════════════════════════════════════════════════╝

🔍 Verifying data collection for CVE-2024-3400...

================================================================================
🔍 SCRAPING VERIFICATION FOR CVE-2024-3400
================================================================================

📊 PHASE 1: Basic Evidence Collection
----------------------------------------

✅ Sources checked: 21
⏱️  Time taken: 3.45s

📌 NVD: 4 data points
   • CVSS Score: 10.0
   • Published: 2024-04-12
   • Description: Command injection vulnerability...

📌 CISA_KEV: 5 data points
   • Listed: Yes
   • Date Added: 2024-04-12
   • Due Date: 2024-05-02
   • Notes: Palo Alto Networks has observed...

📌 GITHUB: 8 data points
   • Advisories: 3
   • PoCs found: 2
   • Stars: 156

📌 HONEYPOT_DATA: 3 data points
   • Detections: 3
   • First seen: 2024-04-11
   • Peak activity: 2024-04-13

[Additional sources...]

📚 PHASE 2: Enhanced Context Collection
----------------------------------------

📖 DOCUMENTATION: 234 items collected
   • Technical docs: 89 pages
   • API references: 45 entries
   • Configuration guides: 100 items

💬 DISCUSSION FORUMS: 567 comments
   • Reddit threads: 12
   • Stack Overflow: 23
   • Security forums: 532

🔧 CODE REPOSITORIES: 45 relevant files
   • Exploit code: 12
   • Detection scripts: 18
   • Patches: 15
```

## 5. Checking System Status

```bash
$ python zero_day_detector.py status

╔═══════════════════════════════════════════════════════════════╗
║     🎯 Zero-Day Vulnerability Detection System v3.12.2        ║
╚═══════════════════════════════════════════════════════════════╝

📊 System Status
--------------------------------------------------
✅ Configuration loaded
   Version: v3.12.2
   Date: 2025-08-04

🎯 Detection Thresholds:
   HIGH: 0.5
   MEDIUM: 0.5
   LOW: 0.45
   VERY_LOW: 0.7

💾 Cache Status:
   Files: 142
   Size: 45.3 MB

🔑 API Configuration:
   OpenRouter API key: ✅ Configured
```

## Common Use Cases

### 1. Quick Zero-Day Check
```bash
# Check if a recent CVE is a zero-day
python zero_day_detector.py detect CVE-2024-3400
```

### 2. Batch Testing for Research
```bash
# Test 100 CVEs for academic research
python zero_day_detector.py download --total 200
python zero_day_detector.py test --zero-days 100 --regular 100
```

### 3. Verify Detection Quality
```bash
# Check what evidence is being collected
python zero_day_detector.py verify CVE-2021-44228

# Test with known examples
python zero_day_detector.py test --zero-days 5 --regular 5
```

### 4. Daily Security Operations
```bash
# Check multiple CVEs from a security bulletin
python zero_day_detector.py detect CVE-2024-3400
python zero_day_detector.py detect CVE-2024-3401
python zero_day_detector.py detect CVE-2024-3402
```

## Usage Notes

1. **Caching**: System implements intelligent caching for efficiency
2. **Parallel Processing**: Supports concurrent analysis for batch operations
3. **Dataset Management**: Efficient dataset handling for large-scale testing
4. **Configuration**: Ensure proper API configuration before use