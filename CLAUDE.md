# Claude Code Session Notes

## Project Overview
- **Project**: Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble
- **Author**: Lorenzo De Tomasi (lorenzo.detomasi@graduate.univaq.it)
- **Purpose**: Academic paper on novel zero-day detection approach

## Current Performance
- **Accuracy**: 80% (24/30 correct)
- **Recall**: 100% (all zero-days detected)
- **Statistical Significance**: p < 0.001
- **Ensemble Boost**: +11-13% over single agents

## Key Features
- Multi-agent LLM ensemble (5 specialized agents)
- Dynamic confidence-based thresholds
- Thompson Sampling for weight optimization
- 8-source evidence collection
- 40+ objective features

## API Configuration
```bash
export OPENROUTER_API_KEY="your-api-key"
```

## Main Commands
```bash
# Main testing command
python test_system.py --zero-days 20 --regular 20

# Quick demo (cached results)
python quick_test.py

# Single CVE analysis
python detect_zero_days.py CVE-2024-3400
```

## Important Notes
- NO MOCKUPS - System must be genuinely functional
- NO HARDCODED VALUES - All detection based on objective features  
- MAINTAIN CHANGELOG - Update with every significant change
- ACADEMIC RIGOR - Results must be reproducible and verifiable