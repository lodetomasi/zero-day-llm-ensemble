# Dataset Management Guide

This guide explains how to manage, download, and create datasets for the Zero-Day Detection System.

## Overview

The system uses various datasets for testing and evaluation:
- **Zero-day CVEs**: Vulnerabilities exploited before patches were available
- **Regular CVEs**: Vulnerabilities disclosed responsibly before exploitation

## Available Scripts

### 1. Download Additional CVEs (`download_more_cves.py`)

Downloads CVEs from multiple sources to expand your dataset.

```bash
python scripts/download_more_cves.py
```

**What it does:**
1. **CISA KEV Download**: Fetches all Known Exploited Vulnerabilities (confirmed zero-days)
2. **NVD Recent CVEs**: Downloads recent vulnerabilities from National Vulnerability Database
3. **Synthetic Generation**: Creates test CVEs for evaluation
4. **Automatic Merging**: Combines with existing datasets

**Output:**
- `data/additional_cves.json`: New CVEs downloaded
- `data/expanded_dataset_merged.json`: Merged with existing data

### 2. Download Regular CVEs (`download_regular_cves.py`)

Specifically targets non-zero-day CVEs to balance datasets.

```bash
python scripts/download_regular_cves.py
```

**What it does:**
1. **Historical CVEs**: Downloads older CVEs (2020-2022) likely to be regular disclosures
2. **Low/Medium Severity**: Fetches CVEs with lower CVSS scores (rarely zero-days)
3. **Responsible Disclosure**: Identifies CVEs with researcher credits
4. **Synthetic Regular CVEs**: Generates realistic regular CVEs with:
   - Vendor/Product information
   - Researcher credits
   - Coordinated disclosure indicators
   - Realistic CVSS distribution

**Output:**
- `data/regular_cves.json`: Regular CVEs only
- `data/balanced_dataset_[100/200/500/1000].json`: Pre-balanced datasets

### 3. Balance Dataset (`balance_dataset.py`)

Creates balanced datasets from existing data.

```bash
# Create specific size
python scripts/balance_dataset.py 100   # 50 zero-days + 50 regular
python scripts/balance_dataset.py 500   # 250 zero-days + 250 regular
python scripts/balance_dataset.py 1000  # 500 zero-days + 500 regular
```

**Features:**
- Random sampling from available CVEs
- Maintains 50/50 balance
- Handles cases where one type has fewer CVEs

## Dataset Structure

Each CVE entry contains:
```json
{
  "CVE-2024-12345": {
    "is_zero_day": true/false,
    "description": "Vulnerability description",
    "source": "CISA KEV/NVD/Synthetic",
    "cvss_score": 7.5,
    "evidence": "Exploitation evidence or disclosure type",
    "vendor": "Microsoft",
    "product": "Windows",
    "researcher_credit": "Security Researcher (for regular CVEs)"
  }
}
```

## Data Sources

### Zero-Day Sources
1. **CISA KEV**: Official list of exploited vulnerabilities
2. **High-severity recent CVEs**: Potential zero-days based on patterns
3. **Generated test data**: For evaluation purposes

### Regular CVE Sources
1. **Historical NVD data**: Older CVEs with patches
2. **Low/Medium severity CVEs**: Less likely to be zero-days
3. **CVEs with researcher credits**: Indicates responsible disclosure
4. **Synthetic data**: Realistic regular CVEs for testing

## Best Practices

### 1. Start with Balanced Datasets
```bash
# First, download regular CVEs to balance
python scripts/download_regular_cves.py

# Then test with balanced data
python zero_day_detector.py test --zero-days 100 --regular 100
```

### 2. Update Datasets Periodically
```bash
# Download latest CVEs monthly
python scripts/download_more_cves.py

# Rebalance after updates
python scripts/balance_dataset.py 500
```

### 3. Verify Dataset Quality
```python
# Check dataset balance
import json

with open('data/balanced_dataset_500.json', 'r') as f:
    data = json.load(f)
    
zero_days = sum(1 for v in data.values() if v['is_zero_day'])
regular = len(data) - zero_days

print(f"Zero-days: {zero_days}")
print(f"Regular: {regular}")
print(f"Balance: {zero_days/len(data)*100:.1f}%")
```

## Troubleshooting

### NVD API Issues
The NVD API may return 404 errors due to:
- Rate limiting
- Required date parameters
- API changes

**Solution**: The scripts automatically fall back to synthetic data generation.

### Imbalanced Results
If you have too many zero-days:
1. Run `download_regular_cves.py` to get more regular CVEs
2. Use `balance_dataset.py` to create balanced sets

### Memory Issues with Large Datasets
For very large datasets (>10,000 CVEs):
1. Process in batches
2. Use the parallel processing options
3. Increase system memory allocation

## Advanced Usage

### Custom Filtering
```python
# Filter CVEs by year
filtered = {k: v for k, v in data.items() 
            if '2024' in k}

# Filter by severity
high_severity = {k: v for k, v in data.items() 
                 if v.get('cvss_score', 0) >= 7.0}

# Filter by vendor
microsoft_cves = {k: v for k, v in data.items() 
                  if v.get('vendor') == 'Microsoft'}
```

### Merge Multiple Sources
```python
import json
from pathlib import Path

# Load all datasets
all_cves = {}
for json_file in Path('data').glob('*.json'):
    with open(json_file, 'r') as f:
        all_cves.update(json.load(f))

# Remove duplicates (keeps first occurrence)
print(f"Total unique CVEs: {len(all_cves)}")
```

## Dataset Statistics

Current dataset capabilities:
- **Maximum zero-days**: 1400+ (from CISA KEV)
- **Maximum regular CVEs**: 600+ (expandable with synthetic data)
- **Recommended test size**: 100-500 CVEs for reasonable runtime
- **Optimal balance**: 50/50 for unbiased evaluation