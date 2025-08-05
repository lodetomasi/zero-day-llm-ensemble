# Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble

A multi-agent Large Language Model ensemble for automated zero-day vulnerability detection through evidence-based analysis.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [System Architecture](#system-architecture)
5. [Methodology](#methodology)
6. [Implementation](#implementation)
7. [Usage](#usage)
8. [Performance](#performance)
9. [Configuration](#configuration)
10. [Project Structure](#project-structure)
11. [Contributing](#contributing)
12. [Citation](#citation)
13. [License](#license)

## Introduction

Zero-day vulnerability detection remains a critical challenge in cybersecurity, requiring rapid identification of actively exploited vulnerabilities before patches are available. Traditional approaches rely heavily on signature-based detection or manual analysis, which struggle to keep pace with the evolving threat landscape.

This system implements a novel multi-agent LLM ensemble that combines:
- **Evidence-based detection** through real-time web scraping from authoritative sources
- **Specialized agent analysis** with five LLMs trained for different detection aspects
- **Dynamic optimization** using Thompson Sampling for adaptive weight adjustment
- **Objective feature engineering** extracting 40+ measurable indicators

### Key Contributions

1. A novel multi-agent LLM ensemble architecture for zero-day vulnerability detection
2. Comprehensive evaluation framework with ground truth verification
3. Statistical validation demonstrating ensemble superiority over single-agent approaches
4. Open-source implementation with reproducible results
5. Dynamic threshold optimization using Thompson Sampling

## Installation

```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
```

### Optional: Install Scrapy for 10x faster scraping
```bash
pip install scrapy>=2.11.0
```

## Quick Start

```bash
# Set API key
export OPENROUTER_API_KEY="your-api-key"

# Analyze a single CVE
python zeroday.py CVE-2024-3400

# Analyze multiple CVEs
python zeroday.py CVE-2024-3400 CVE-2021-44228 CVE-2023-1234

# JSON output for automation
python zeroday.py --json CVE-2024-3400

# Run comprehensive test suite
python scripts/run_comprehensive_test.py
```

## System Architecture

```
CVE Input
    ↓
TurboScraper (10x faster with Scrapy)
    ↓
Evidence Collection (21+ sources)
    • CISA KEV & NVD
    • Security advisories
    • GitHub & ExploitDB
    • Threat intelligence
    • Bug bounty platforms
    • Honeypot networks
    • Social media monitoring
    • Academic papers
    • Government alerts
    • Darkweb forums
    ↓
Feature Extraction (43+ indicators)
    • in_cisa_kev (weight: 0.60)
    • rapid_kev_addition (weight: 0.25)
    • has_exploit_code (weight: 0.30)
    • actively_exploited (weight: 0.40)
    • apt_association (weight: 0.25)
    • emergency_patch (weight: 0.20)
    • high_value_target (weight: 0.15)
    • [36+ additional features]
    ↓
Multi-Agent Analysis (5 parallel agents)
    • ForensicAnalyst (Mixtral 8x22B)
    • PatternDetector (Claude Opus)
    • TemporalAnalyst (Llama 3.3 70B)
    • AttributionExpert (DeepSeek)
    • MetaAnalyst (Gemini 2.5 Pro)
    ↓
Thompson Sampling (Dynamic Weights)
    • Adaptive weight optimization
    • Performance-based adjustment
    • Exploration vs exploitation
    ↓
Score Combination
    60% features + 30% LLM + 10% threat
    ↓
Dynamic Threshold Decision
    • HIGH confidence → 0.50
    • MEDIUM confidence → 0.45
    • LOW confidence → 0.40
    • VERY_LOW confidence → 0.35
    ↓
Zero-Day Detection Result
```

## Methodology

### Evidence Collection

The system employs **TurboScraper**, a high-performance parallel scraping engine built on Scrapy, collecting data from 21+ sources:

**Primary Sources:**
- National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- MITRE ATT&CK framework
- ExploitDB and GitHub repositories

**Intelligence Sources:**
- Government security alerts (US-CERT, etc.)
- Security researcher analyses
- Bug bounty platform reports
- Honeypot detection networks
- Threat intelligence feeds
- Social media monitoring

**Additional Context:**
- Academic papers and research
- Patch timeline analysis
- Vendor advisories
- Community discussions

### Feature Engineering

The system extracts 43+ objective features grouped into categories:

**Temporal Features:**
- Days between disclosure and CISA KEV addition
- PoC availability timeline
- Patch release velocity
- Exploitation window analysis

**Evidence Features:**
- CISA KEV inclusion (strongest indicator)
- Multiple exploit variants
- APT group associations
- Ransomware campaign usage

**Technical Features:**
- CVSS scores and metrics
- Attack complexity
- Required privileges
- Network vs local exploitation

**Social Features:**
- Security community buzz
- GitHub activity metrics
- Social media mentions
- Bug bounty reports

### Multi-Agent Ensemble

Five specialized agents analyze different aspects:

1. **ForensicAnalyst**: Deep technical analysis of vulnerability characteristics
2. **PatternDetector**: Historical pattern matching against known zero-days
3. **TemporalAnalyst**: Timeline analysis for anomaly detection
4. **AttributionExpert**: Threat actor behavior and attribution
5. **MetaAnalyst**: Cross-agent validation and consensus building

### Thompson Sampling

Dynamic weight optimization based on agent performance:
- Maintains success/failure counters for each agent
- Samples weights from Beta distributions
- Balances exploration of new patterns vs exploitation of known signals
- Adapts to evolving threat landscape

### Scoring Algorithm

```python
# Feature-based scoring with evidence weights
feature_score = sum(feature_value * feature_weight for feature in features)

# LLM ensemble scoring with Thompson Sampling
llm_weights = thompson_sampler.sample()
llm_score = sum(agent_score * weight for agent_score, weight in zip(agent_scores, llm_weights))

# Threat actor interest scoring
threat_score = calculate_threat_interest(evidence)

# Final combination
final_score = 0.60 * feature_score + 0.30 * llm_score + 0.10 * threat_score

# Dynamic threshold based on confidence
threshold = select_threshold(confidence_level)
is_zero_day = final_score >= threshold
```

## Implementation

### Core Components

- **`src/scraping/turbo_scraper.py`**: High-performance parallel scraping with Scrapy
- **`src/utils/feature_extractor.py`**: Evidence-based feature extraction (43+ features)
- **`src/ensemble/multi_agent.py`**: Parallel agent coordination and management
- **`src/ensemble/thompson.py`**: Thompson Sampling for dynamic optimization
- **`src/agents/`**: Individual agent implementations with specialized prompts

### Key Features

- **Parallel Processing**: All agents analyze concurrently for speed
- **Smart Caching**: Multi-tier cache (Hot/Warm/Cold) reduces API calls
- **Error Resilience**: Graceful degradation when sources unavailable
- **Modular Design**: Easy to add new agents or data sources
- **Type Safety**: Full type hints for better code quality

## Usage

### Command Line Interface

```bash
# Basic detection
python zeroday.py CVE-2024-3400

# Detailed analysis
python zeroday.py -d CVE-2024-3400

# Quiet mode (result only)
python zeroday.py -q CVE-2024-3400

# Multiple CVEs
python zeroday.py CVE-2024-3400 CVE-2021-44228 CVE-2023-1234

# JSON output
python zeroday.py --json CVE-2024-3400

# Disable TurboScraper
python zeroday.py --no-turbo CVE-2024-3400
```

### Testing Framework

```bash
# Run comprehensive test with metrics
python scripts/run_comprehensive_test.py

# Save detailed results
python scripts/run_comprehensive_test.py --output results.json

# Validate ground truth
python scripts/validate_ground_truth.py

# Fix ground truth if needed
python scripts/validate_ground_truth.py --fix

# Calculate metrics from results
python scripts/calculate_metrics.py results.json
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

## Performance

### System Characteristics

- **High Precision**: Minimal false positives through evidence-based approach
- **Balanced Detection**: Consistent performance across vulnerability types
- **Statistical Significance**: Ensemble outperforms single agents (p < 0.001)
- **Fast Analysis**: ~2-3 seconds per CVE with TurboScraper
- **Scalable**: Batch processing for large-scale analysis

### Optimization Strategies

1. **TurboScraper**: 10x faster data collection with Scrapy
2. **Parallel Agents**: Concurrent analysis reduces latency
3. **Smart Caching**: Reduces redundant API calls
4. **Batch Processing**: Efficient multi-CVE analysis
5. **Adaptive Thresholds**: Confidence-based decision boundaries

### Ablation Study Results

- All agents contribute positively to ensemble performance
- Thompson Sampling effectively balances agent contributions
- Feature-based evidence provides strong baseline
- LLM analysis adds nuanced pattern recognition

## Configuration

### Environment Variables

```bash
# Required
export OPENROUTER_API_KEY="your-api-key"

# Optional
export ZERO_DAY_LOG_LEVEL="INFO"
export ZERO_DAY_CACHE_DIR="/path/to/cache"
```

### Model Configuration

Edit `config/models.yaml` to customize models:

```yaml
agents:
  ForensicAnalyst:
    model: "mistralai/mixtral-8x22b-instruct"
    max_tokens: 500
    temperature: 0.3
  
  PatternDetector:
    model: "anthropic/claude-opus-4"
    max_tokens: 500
    temperature: 0.3
```

### Detection Thresholds

Adjust in `scripts/detect_zero_days_enhanced.py`:

```python
self.detection_threshold = 0.5  # Base threshold
self.confidence_thresholds = {
    'HIGH': 0.50,
    'MEDIUM': 0.45,
    'LOW': 0.40,
    'VERY_LOW': 0.35
}
```

## Project Structure

```
zero-day-llm-ensemble/
├── zeroday.py              # Main CLI interface
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── CHANGELOG.md           # Version history
├── METHODOLOGY.md         # Detailed methodology
├── LICENSE                # MIT License
│
├── src/                   # Core source code
│   ├── agents/           # LLM agent implementations
│   ├── ensemble/         # Ensemble logic
│   ├── scraping/         # Data collection
│   └── utils/            # Utilities
│
├── scripts/              # Utility scripts
│   ├── detect_zero_days_enhanced.py
│   ├── run_comprehensive_test.py
│   ├── validate_ground_truth.py
│   └── calculate_metrics.py
│
├── config/               # Configuration
│   ├── models.yaml      # LLM models
│   ├── prompts.yaml     # Agent prompts
│   └── settings.py      # System settings
│
├── data/                # Data files
│   └── test_cves_100.json  # Test dataset
│
└── tests/               # Unit tests
    └── test_agents.py
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- Additional data sources
- New agent types
- Performance optimizations
- Documentation improvements
- Test coverage expansion

## Related Work

This system builds upon research in:
- Vulnerability detection using machine learning
- LLM applications in cybersecurity
- Ensemble methods for classification
- Thompson Sampling for online learning

See the paper for detailed literature review and comparisons.

## Citation

If you use this system in your research, please cite:

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

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- University of L'Aquila for research support
- CISA for maintaining the KEV database
- OpenRouter for LLM API access
- The security research community for valuable insights

## Contact

Lorenzo De Tomasi  
Department of Information Engineering, Computer Science and Mathematics  
University of L'Aquila, Italy  
lorenzo.detomasi@graduate.univaq.it

---

For more details, see [METHODOLOGY.md](METHODOLOGY.md) and [CHANGELOG.md](CHANGELOG.md).