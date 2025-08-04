# Usage Guide

Learn how to use the Zero-Day LLM Ensemble system for vulnerability detection and analysis.

## 🚀 Quick Start

### Detect a Single CVE

```bash
python scripts/detect_zero_days.py CVE-2024-3400
```

Add `-v` for verbose output:
```bash
python scripts/detect_zero_days.py CVE-2024-3400 -v
```

### Run Cached Demo

View results from 30 pre-analyzed CVEs (no API calls):
```bash
python scripts/quick_test.py
```

## 🧪 Running Tests

### Balanced Testing

Test with specific numbers of zero-days and regular CVEs:

```bash
# Test 10 zero-days and 10 regular CVEs
python scripts/test_system.py --zero-days 10 --regular 10

# List available verified CVEs
python scripts/test_system.py --list-available
```

### Cross-Validation

Run 5-fold cross-validation:
```bash
python scripts/run_cross_validation.py
```

### Ablation Study

Test individual agents and combinations:
```bash
python scripts/run_ablation_study.py
```

## 📊 Understanding Results

### Detection Output

When analyzing a CVE, you'll see:

```
🔍 Analyzing CVE-2024-3400 for zero-day detection
============================================================
📡 Step 1: Collecting web evidence...
📊 Step 2: Extracting objective features...
🤖 Step 3: Running multi-agent LLM analysis...

============================================================
🎯 DETECTION RESULT: ZERO-DAY DETECTED
============================================================

📊 Detection Score: 84.8%
   Confidence: 69.0% (MEDIUM)
   Agent Consensus: 80.0%

🔍 Key Indicators:
   • Listed in CISA KEV
   • Rapid KEV addition (<7 days)
   • Exploitation before patch
   • Emergency patches released

💭 Reasoning: Detected as zero-day based on: CISA KEV listing, pre-patch exploitation
```

### Metrics Explanation

- **Detection Score**: 0-100% likelihood of being a zero-day
- **Confidence**: How certain the system is about its prediction
- **Agent Consensus**: Agreement level among the 5 LLM agents
- **Key Indicators**: Objective evidence supporting the decision

## 🔧 Advanced Usage

### Batch Analysis

Analyze multiple CVEs:
```bash
python scripts/detect_zero_days.py CVE-2024-3400 CVE-2023-20198 CVE-2022-30190
```

### Custom Datasets

Create your own test dataset:
```bash
python scripts/create_verified_dataset.py --zero-days 20 --regular 20
```

### Statistical Analysis

Run statistical significance tests:
```bash
python scripts/run_statistical_tests.py
```

## 📁 Output Files

Results are saved in:
- `detection_reports/` - Individual CVE analysis reports
- `results/` - Aggregated test results and evaluations
- `data/cache/` - Cached detection results for efficiency

## ⚙️ Configuration

### Adjust Detection Thresholds

Edit `config/optimized_thresholds.json`:
```json
{
  "detection_thresholds": {
    "by_confidence": {
      "HIGH": 0.70,
      "MEDIUM": 0.83,
      "LOW": 0.67,
      "VERY_LOW": 0.65
    }
  }
}
```

### Model Configuration

Edit `config/models.yaml` to change LLM models or parameters.

## 💡 Best Practices

1. **Start Small**: Test with 5-10 CVEs before large-scale analysis
2. **Use Cache**: The system caches results for 7 days
3. **Monitor Credits**: Check API usage with credit monitoring
4. **Verify Ground Truth**: Always validate results against public sources

## 🔍 Interpreting Results

### High Confidence Predictions
- Score > 80% with HIGH confidence = Very likely zero-day
- Score < 20% with HIGH confidence = Very likely NOT zero-day

### Low Confidence Predictions
- Require manual review
- Check the key indicators and reasoning
- Verify against external sources

## 📈 Performance Tips

- Run in parallel mode (default) for faster analysis
- Use cached results when re-testing
- Batch CVEs to minimize overhead
- Set appropriate rate limits to avoid API throttling