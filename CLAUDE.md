# Claude Code Session Notes

This file maintains important context for consistency across Claude Code sessions.

## Project Overview
- **Project**: Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble
- **Author**: Lorenzo De Tomasi (lorenzo.detomasi@graduate.univaq.it)
- **Institution**: University of L'Aquila, Italy
- **Purpose**: Academic paper on novel zero-day detection approach

## Key Requirements
1. **NO MOCKUPS**: System must be genuinely functional
2. **NO HARDCODED VALUES**: All detection based on objective features
3. **MAINTAIN CHANGELOG**: Update CHANGELOG.md with every significant change
4. **ACADEMIC RIGOR**: Results must be reproducible and verifiable

## Current Performance
- **Accuracy**: 80% (24/30 correct on large-scale test)
- **Precision**: 76% (low false positives)
- **Recall**: 100% (all zero-days detected)
- **F1-Score**: 0.864

## Important Files
- `detect_zero_days.py`: Main detection script with dynamic thresholds
- `verify_ground_truth.py`: Verifies dataset labels against public sources
- `create_verified_dataset.py`: Creates clean datasets with proper labels
- `run_large_scale_test.py`: Runs comprehensive evaluation

## Dynamic Thresholds
The system uses confidence-based dynamic thresholds:
- HIGH confidence (≥80%): threshold = 0.70
- MEDIUM confidence (60-80%): threshold = 0.83
- LOW confidence (40-60%): threshold = 0.67
- VERY_LOW confidence (<40%): threshold = 0.65

## Ground Truth Corrections
6 CVEs were corrected based on public verification:
- CVE-2021-42287: zero-day → regular (researcher disclosure)
- CVE-2020-1472: zero-day → regular (Zerologon)
- CVE-2019-0708: zero-day → regular (BlueKeep)
- CVE-2022-22965: regular → zero-day (Spring4Shell)
- CVE-2023-35078: regular → zero-day (Ivanti)
- CVE-2023-22515: regular → zero-day (Confluence)

## API Configuration
- API Key stored in `.env` file
- Key: `OPENROUTER_API_KEY`
- Used for multi-agent LLM ensemble

## Testing Commands
```bash
# Single CVE test
python detect_zero_days.py CVE-2024-3400 -v

# Large-scale evaluation
python run_large_scale_test.py --limit 50

# Verify ground truth
python verify_ground_truth.py

# Create clean dataset
python create_verified_dataset.py
```

## Next Steps
- Continue improving detection accuracy while maintaining 100% recall
- Add more objective features for better discrimination
- Expand to real-time monitoring capabilities