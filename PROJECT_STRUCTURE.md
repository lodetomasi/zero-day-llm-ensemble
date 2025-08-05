# Project Structure

## Directory Layout

```
zero-day-llm-ensemble/
├── zeroday.py              # Main CLI interface
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── CHANGELOG.md           # Version history
├── METHODOLOGY.md         # Detection methodology
├── LICENSE                # MIT License
│
├── src/                   # Core source code
│   ├── agents/           # LLM agent implementations
│   │   ├── base_agent.py
│   │   ├── attribution.py
│   │   ├── forensic.py
│   │   ├── meta.py
│   │   ├── pattern.py
│   │   └── temporal.py
│   │
│   ├── ensemble/         # Ensemble logic
│   │   ├── multi_agent.py
│   │   ├── thompson.py
│   │   └── threshold_manager.py
│   │
│   ├── scraping/         # Data collection
│   │   ├── turbo_scraper.py      # 10x faster Scrapy
│   │   ├── comprehensive_scraper.py
│   │   └── smart_cache.py
│   │
│   └── utils/            # Utilities
│       ├── feature_extractor.py
│       ├── llm_formatter.py
│       ├── logger.py
│       └── credit_monitor.py
│
├── scripts/              # Utility scripts
│   ├── detect_zero_days_enhanced.py
│   ├── run_comprehensive_test.py
│   ├── validate_ground_truth.py
│   ├── calculate_metrics.py
│   └── generate_test_cves.py
│
├── config/               # Configuration
│   ├── models.yaml      # LLM model config
│   ├── prompts.yaml     # Agent prompts
│   └── settings.py      # System settings
│
├── data/                # Data files
│   ├── test_cves_100.json    # Test dataset
│   └── cache/                # API cache
│
├── tests/               # Unit tests
│   └── test_agents.py
│
└── docs/                # Documentation
    └── QUICKSTART.md
```

## Key Files

### Main Entry Points
- `zeroday.py` - Clean CLI for single/multiple CVE analysis
- `scripts/run_comprehensive_test.py` - Full test suite with metrics

### Core Components
- `src/scraping/turbo_scraper.py` - High-performance data collection
- `src/utils/feature_extractor.py` - Evidence-based feature extraction
- `src/ensemble/multi_agent.py` - Multi-agent coordination
- `src/ensemble/thompson.py` - Dynamic weight optimization

### Test Data
- `test_cves_100.json` - 100 CVEs with verified ground truth (63 zero-days, 37 regular)

## Workflow

1. **Input**: CVE ID(s)
2. **Scraping**: TurboScraper collects evidence from 21+ sources
3. **Features**: Extract 43+ indicators including CISA KEV
4. **Analysis**: 5 LLM agents analyze in parallel
5. **Ensemble**: Thompson Sampling combines predictions
6. **Output**: Zero-day detection with confidence score

## Clean Architecture

- No hardcoded CVE scores
- Evidence-based detection
- Verified ground truth
- Minimal dependencies
- Production-ready logging