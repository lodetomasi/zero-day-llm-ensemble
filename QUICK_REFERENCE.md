# Quick Reference

## Essential Commands

### Single CVE Analysis
```bash
python zeroday.py CVE-2024-3400
```

### Multiple CVEs
```bash
python zeroday.py CVE-2024-3400 CVE-2021-44228 CVE-2023-1234
```

### JSON Output
```bash
python zeroday.py --json CVE-2024-3400
```

### Quiet Mode
```bash
python zeroday.py -q CVE-2024-3400
```

### Show Details
```bash
python zeroday.py -d CVE-2024-3400
```

## Testing

### Run Full Test (100 CVEs)
```bash
python scripts/run_comprehensive_test.py
```

### Save Test Results
```bash
python scripts/run_comprehensive_test.py --output results.json
```

### Validate Ground Truth
```bash
python scripts/validate_ground_truth.py
```

### Calculate Metrics
```bash
python scripts/calculate_metrics.py results.json
```

## Key Files

- **Main CLI**: `zeroday.py`
- **Test Dataset**: `test_cves_100.json` (63 zero-days, 37 regular)
- **Configuration**: `config/models.yaml`
- **API Key**: Set `OPENROUTER_API_KEY` environment variable

## Performance

- **Speed**: ~2-3 seconds per CVE with TurboScraper
- **Accuracy**: ~70% (100% precision, 51% recall)
- **Ground Truth**: 100% verified against CISA KEV

## Troubleshooting

### API Credits Exhausted
```
Error 402: This request requires more credits
```
Solution: Add credits at https://openrouter.ai/settings/credits

### Slow Performance
- Check if TurboScraper is enabled (default)
- Verify internet connection
- Check API rate limits