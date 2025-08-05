# Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble

A multi-agent Large Language Model ensemble for automated zero-day vulnerability detection through evidence-based analysis.

## Installation

```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
```

## Quick Start

```bash
# Set API key
export OPENROUTER_API_KEY="your-api-key"

# Analyze a CVE
python zeroday.py CVE-2024-3400

# Multiple CVEs
python zeroday.py CVE-2024-3400 CVE-2021-44228

# JSON output
python zeroday.py --json CVE-2024-3400
```

## Overview

This system implements a novel approach to zero-day vulnerability detection using multiple Large Language Model agents working in ensemble. By combining comprehensive evidence collection, objective feature engineering, and specialized agent analysis, the system provides automated vulnerability assessment for security practitioners and researchers.

### Key Features

- **Multi-Agent Analysis**: Five specialized LLM agents analyzing different aspects of vulnerabilities
- **Evidence-Based Detection**: Comprehensive data collection from 21+ authoritative sources
- **Dynamic Optimization**: Thompson Sampling for adaptive weight adjustment
- **Fast Performance**: TurboScraper with Scrapy for parallel data collection
- **Transparent Methodology**: Feature-based scoring with documented weights

## System Architecture

```
CVE Input
    ↓
TurboScraper (Parallel Evidence Collection)
    ↓
Feature Extraction (43+ indicators)
    • CISA KEV inclusion
    • Exploit availability
    • Active exploitation
    • Timeline analysis
    ↓
Multi-Agent Analysis
    • ForensicAnalyst: Technical vulnerability analysis
    • PatternDetector: Exploitation pattern recognition
    • TemporalAnalyst: Timeline anomaly detection
    • AttributionExpert: Threat actor attribution
    • MetaAnalyst: Consensus building
    ↓
Ensemble Decision (Thompson Sampling)
    ↓
Detection Result with Confidence Score
```

## Methodology

### Evidence Collection

The system collects data from multiple sources including:
- National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- Security advisories and bulletins
- Exploit databases
- Threat intelligence feeds
- Security research publications

### Feature Engineering

Evidence-based features are extracted with specific weights:
- CISA KEV listing (primary indicator)
- Rapid exploitation timeline
- Exploit code availability
- Active exploitation reports
- APT group associations
- Emergency patch releases

### Multi-Agent Ensemble

Five specialized agents analyze different aspects:
1. **ForensicAnalyst**: Technical vulnerability characteristics
2. **PatternDetector**: Historical exploitation patterns
3. **TemporalAnalyst**: Timeline and disclosure analysis
4. **AttributionExpert**: Threat actor behavior patterns
5. **MetaAnalyst**: Cross-agent consensus and validation

### Score Combination

Final detection uses weighted combination:
- Feature evidence: 60%
- LLM analysis: 30%
- Threat indicators: 10%

## Usage

### Command Line Interface

```bash
# Basic usage
python zeroday.py CVE-2024-3400

# With detailed output
python zeroday.py -d CVE-2024-3400

# Quiet mode (result only)
python zeroday.py -q CVE-2024-3400

# JSON output for automation
python zeroday.py --json CVE-2024-3400
```

### Testing and Evaluation

```bash
# Run comprehensive test suite
python scripts/run_comprehensive_test.py

# Validate ground truth
python scripts/validate_ground_truth.py

# Calculate metrics from results
python scripts/calculate_metrics.py results.json
```

## Configuration

### API Setup

Set your OpenRouter API key:
```bash
export OPENROUTER_API_KEY="your-api-key"
```

### Model Configuration

Models can be configured in `config/models.yaml`. Default models:
- ForensicAnalyst: Mixtral 8x22B
- PatternDetector: Claude Opus
- TemporalAnalyst: Llama 3.3 70B
- AttributionExpert: DeepSeek
- MetaAnalyst: Gemini 2.5 Pro

## Performance

The system demonstrates strong performance characteristics:
- High precision with minimal false positives
- Balanced detection across vulnerability types
- Statistically significant improvements over single-agent baselines
- Consistent performance across different datasets

### Optimization

- **TurboScraper**: Parallel scraping for faster data collection
- **Smart Caching**: Reduces redundant API calls
- **Thompson Sampling**: Dynamic weight optimization
- **Batch Processing**: Efficient multi-CVE analysis

## Project Structure

```
zero-day-llm-ensemble/
├── zeroday.py              # Main CLI interface
├── src/
│   ├── agents/            # LLM agent implementations
│   ├── ensemble/          # Ensemble logic and Thompson sampling
│   ├── scraping/          # Data collection modules
│   └── utils/             # Feature extraction and utilities
├── scripts/               # Testing and evaluation scripts
├── config/                # Configuration files
├── data/                  # Test datasets
└── docs/                  # Additional documentation
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Citation

If you use this system in your research, please cite:

```bibtex
@software{detomasi2025zerodayensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- University of L'Aquila for research support
- CISA for maintaining the KEV database
- OpenRouter for LLM API access

## Contact

Lorenzo De Tomasi  
Department of Information Engineering, Computer Science and Mathematics  
University of L'Aquila, Italy  
lorenzo.detomasi@graduate.univaq.it