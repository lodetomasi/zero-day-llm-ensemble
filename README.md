# Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble

An advanced system for automated zero-day vulnerability detection using a multi-agent Large Language Model ensemble with evidence-based analysis.

## Quick Start

```bash
# Clone repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Install dependencies
pip install -r requirements.txt

# Set API key
export OPENROUTER_API_KEY="your-api-key"

# Analyze a CVE
python zeroday.py CVE-2024-3400
```

## Features

- **Multi-Agent LLM Ensemble**: 5 specialized agents analyze vulnerabilities from different perspectives
- **Evidence-Based Detection**: Collects data from 21+ authoritative sources including CISA KEV, NVD, ExploitDB
- **43+ Objective Features**: Extracts measurable indicators like CISA KEV inclusion, exploit availability, social signals
- **Thompson Sampling**: Dynamic weight optimization for adaptive agent performance
- **TurboScraper**: 10x faster data collection using Scrapy framework
- **Smart Caching**: Multi-tier cache system reduces API calls and improves performance

## System Architecture

```
CVE Input → TurboScraper → Evidence Collection (21+ sources)
    ↓
Feature Extraction (43+ indicators)
    ↓
Multi-Agent Analysis (5 parallel LLMs)
    ↓
Thompson Sampling (Dynamic Weights)
    ↓
Score Combination (60% features + 30% LLM + 10% threat)
    ↓
Zero-Day Detection Result
```

## Installation

### Requirements
- Python 3.8+
- OpenRouter API key for LLM access

### Setup
```bash
pip install -r requirements.txt
```

### Optional: Install Scrapy for faster scraping
```bash
pip install scrapy>=2.11.0
```

## Usage

### Command Line Interface

```bash
# Basic detection
python zeroday.py CVE-2024-3400

# Multiple CVEs
python zeroday.py CVE-2024-3400 CVE-2021-44228 CVE-2023-1234

# JSON output for automation
python zeroday.py --json CVE-2024-3400

# Quiet mode (result only)
python zeroday.py -q CVE-2024-3400
```

### Python API

```python
from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector

# Initialize detector
detector = EnhancedZeroDayDetector(use_turbo=True)

# Analyze CVE
result = detector.detect("CVE-2024-3400", verbose=True)

# Access results
print(f"Is Zero-Day: {result['is_zero_day']}")
print(f"Confidence: {result['confidence']:.1%}")
print(f"Key Evidence: {result['key_indicators']}")
```

## Testing

```bash
# Run comprehensive test suite
python scripts/run_comprehensive_test.py

# Validate ground truth
python scripts/validate_ground_truth.py

# Generate test datasets
python scripts/generate_test_cves.py
```

## Configuration

### Environment Variables
```bash
export OPENROUTER_API_KEY="your-api-key"
export ZERO_DAY_LOG_LEVEL="INFO"  # Optional
```

### Model Configuration
Edit `config/models.yaml` to customize LLM models:
```yaml
agents:
  ForensicAnalyst:
    model: "mistralai/mixtral-8x22b-instruct"
  PatternDetector:
    model: "anthropic/claude-opus-4"
```

## Project Structure

```
zero-day-llm-ensemble/
├── zeroday.py              # Main CLI interface
├── src/                    # Core source code
│   ├── agents/            # LLM agent implementations
│   ├── ensemble/          # Ensemble logic & Thompson Sampling
│   ├── scraping/          # TurboScraper & data collection
│   └── utils/             # Feature extraction & utilities
├── scripts/               # Analysis & testing scripts
├── config/                # Configuration files
└── data/                  # Test datasets
```

## How It Works

1. **Evidence Collection**: TurboScraper fetches data from CISA KEV, NVD, ExploitDB, GitHub, Reddit, and more
2. **Feature Extraction**: Analyzes evidence to extract 43+ objective indicators
3. **Multi-Agent Analysis**: 5 specialized LLMs analyze the vulnerability:
   - ForensicAnalyst: Technical vulnerability characteristics
   - PatternDetector: Historical zero-day patterns
   - TemporalAnalyst: Timeline anomalies
   - AttributionExpert: Threat actor behavior
   - MetaAnalyst: Cross-agent validation
4. **Dynamic Scoring**: Thompson Sampling optimizes agent weights based on performance
5. **Decision Making**: Combines feature scores (60%), LLM consensus (30%), and threat signals (10%)

## Performance

- **Analysis Speed**: ~2-3 seconds per CVE with TurboScraper
- **High Precision**: Minimal false positives through evidence-based approach
- **Scalable**: Batch processing for large-scale analysis
- **Adaptive**: Thompson Sampling continuously improves detection

## Research & Citation

```bibtex
@software{detomasi2025zerodayensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble},
  institution = {University of L'Aquila}
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contact

Lorenzo De Tomasi  
University of L'Aquila, Italy  
lorenzo.detomasi@graduate.univaq.it