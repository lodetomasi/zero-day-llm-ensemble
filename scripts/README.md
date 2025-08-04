# Scripts Directory

## Core Detection Scripts

### 🎯 `universal_tester.py` - Main Testing System
Universal testing framework that handles any number of CVEs dynamically.

```bash
# Test with 60 CVEs (30 zero-days + 30 regular)
python scripts/universal_tester.py --zero-days 30 --regular 30

# Test all CVEs from 2024
python scripts/universal_tester.py --pattern "CVE-2024-.*"

# Fast parallel testing
python scripts/universal_tester.py --total 100 --parallel --workers 8

# Test all available CVEs
python scripts/universal_tester.py --all
```

### 🔍 `detect_zero_days.py` - Standard Detector
Base zero-day detection system using multi-agent LLM ensemble.

```bash
python scripts/detect_zero_days.py CVE-2024-3400
```

### 🚀 `detect_zero_days_enhanced.py` - Enhanced Detector
Enhanced detection with additional intelligence sources (government alerts, honeypots, social media, etc.)

```bash
python scripts/detect_zero_days_enhanced.py CVE-2024-3400 -v
```

### ⚡ `quick_test.py` - Quick Demo
Fast demonstration using cached results (for presentations).

```bash
python scripts/quick_test.py
```

### 📊 `test_system.py` - Academic Paper Testing
Original testing script for the academic paper (tests 40 CVEs).

```bash
python scripts/test_system.py --zero-days 20 --regular 20
```

## Analysis Scripts

### 📈 `run_statistical_tests.py`
Statistical validation including hypothesis testing and significance analysis.

### 🔬 `run_ablation_study.py`
Ablation study to evaluate contribution of each agent.

### 🔄 `run_cross_validation.py`
K-fold cross-validation for robust evaluation.

### 🤖 `create_ml_baselines.py`
Create traditional ML baselines for comparison.

### 🐛 `analyze_baseline_issue.py`
Debug and analyze baseline performance issues.

## Archived Scripts
Scripts in `archive/` directory have been replaced by the universal tester but are kept for reference:
- `test_60_cves.py` - Replaced by universal_tester.py
- `expand_dataset.py` - Dataset expansion now integrated
- `create_verified_dataset.py` - Datasets already created
- Others for data acquisition and verification

## Usage Priority
1. **For testing**: Use `universal_tester.py` - it's the most flexible and complete
2. **For single CVE analysis**: Use `detect_zero_days_enhanced.py` 
3. **For demos**: Use `quick_test.py`
4. **For paper replication**: Use `test_system.py`