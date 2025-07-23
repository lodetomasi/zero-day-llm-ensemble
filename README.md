# Zero-Day LLM Ensemble

![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Research](https://img.shields.io/badge/status-research-orange.svg?style=for-the-badge)
![Models](https://img.shields.io/badge/models-5_LLMs-purple.svg?style=for-the-badge)

> Multi-agent ensemble leveraging state-of-the-art LLMs for zero-day vulnerability detection without data leakage

## Overview

This project demonstrates that Large Language Models can effectively identify zero-day vulnerabilities from CVE descriptions alone, achieving 70% accuracy with an ensemble of specialized agents. Unlike traditional approaches, our system operates without access to exploitation timestamps or source labels, making it suitable for real-world deployment.

## ✨ Key Features

- **Multi-Agent Architecture** - Five specialized LLMs analyzing vulnerabilities from distinct perspectives
- **Zero Data Leakage** - Classification based solely on CVE content without source indicators  
- **Production Ready** - RESTful API with caching and parallel execution support
- **Comprehensive Analysis** - Automated performance metrics and visualization suite
- **Extensible Design** - Easy integration of new models and analysis strategies

## 📊 Performance

| Metric | Value | Description |
|--------|-------|-------------|
| **Accuracy** | 70% | Overall classification performance |
| **Precision** | 80% | Low false positive rate |
| **Recall** | 45% | Conservative detection approach |
| **Specificity** | 95% | Excellent regular CVE identification |

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set API key
export OPENROUTER_API_KEY="your-api-key"
```

### Basic Usage

```bash
# Quick test (20 CVEs, ~5 minutes)
python run_complete_test.py --zero-days 10 --regular 10 --parallel

# Research evaluation (100 CVEs, ~30 minutes)
python run_complete_test.py --zero-days 50 --regular 50 --parallel

# Custom parameters
python run_complete_test.py \
    --zero-days 25 \
    --regular 25 \
    --parallel \
    --seed 42 \
    --output-dir results/experiment1
```

## 🏗️ Architecture

### System Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Data Collection Layer                     │
│                 CISA KEV API + NVD API                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                   Preprocessing Pipeline                     │
│              Source Anonymization + Validation               │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                  Multi-Agent LLM Ensemble                    │
├─────────────────────────────────────────────────────────────┤
│  Forensic    Pattern    Temporal    Attribution    Meta     │
│  Analyst     Detector   Analyst     Expert        Analyst   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                    Ensemble Aggregation                      │
│                  Binary Classification (>0.5)                │
└─────────────────────────────────────────────────────────────┘
```

### Agent Specializations

| Agent | Model | Focus Area |
|-------|-------|------------|
| **ForensicAnalyst** | Mixtral-8x22B | Exploitation indicators and attack patterns |
| **PatternDetector** | Claude Opus 4 | Linguistic anomalies and technical markers |
| **TemporalAnalyst** | Llama 3.3 70B | Timeline analysis and urgency signals |
| **AttributionExpert** | DeepSeek R1 | Threat actor profiling and targeting |
| **MetaAnalyst** | Gemini 2.5 Pro | Cross-agent synthesis and final verdict |

## 📖 Documentation

### Command-Line Interface

```bash
python run_complete_test.py [OPTIONS]

Required:
  --zero-days N        Number of zero-day CVEs to test
  --regular N          Number of regular CVEs to test

Optional:
  --parallel           Enable parallel execution (recommended)
  --seed N             Random seed for reproducibility
  --output-dir PATH    Custom output directory
  --verbose            Detailed logging
  --no-visualizations  Skip plot generation
  --timeout SECONDS    API timeout per agent (default: 60)
```

### Programmatic API

```python
from src.ensemble.multi_agent import MultiAgentSystem
from src.data.preprocessor import DataPreprocessor

# Initialize system
system = MultiAgentSystem(parallel_execution=True)
preprocessor = DataPreprocessor()

# Analyze CVE
cve_data = {
    'cve_id': 'CVE-2024-1234',
    'vendor': 'Microsoft', 
    'product': 'Windows',
    'description': 'Remote code execution vulnerability...',
    'year': 2024
}

processed = preprocessor.preprocess_entry(cve_data)
result = system.analyze_vulnerability(processed)

# Results
print(f"Zero-day probability: {result['ensemble']['prediction']:.1%}")
print(f"Confidence: {result['ensemble']['confidence']:.1%}")
```

## ⚙️ Configuration

### Environment Variables

```bash
export OPENROUTER_API_KEY="your-api-key"       # Required
export LOG_LEVEL="INFO"                        # Optional: DEBUG, INFO, WARNING
export CACHE_DIR="./cache"                     # Optional: Custom cache location
```

### Model Configuration

Edit `config/settings.py` to customize models:

```python
MODEL_CONFIGS = {
    'ForensicAnalyst': 'mistralai/mixtral-8x22b-instruct',
    'PatternDetector': 'anthropic/claude-opus-4',
    # ... other models
}
```

## 📊 Output

The system generates:

- `results/complete_test_TIMESTAMP.json` - Raw predictions and agent responses
- `results/analysis_plots_TIMESTAMP.png` - 6-panel visualization suite
- `results/report_TIMESTAMP.txt` - Statistical summary

### Visualization Suite

1. **Confusion Matrix** - True/False positive/negative breakdown
2. **Performance Metrics** - Accuracy, Precision, Recall, F1 comparison
3. **Score Distribution** - Probability histograms by class
4. **ROC Curve** - Receiver Operating Characteristic analysis
5. **Prediction Timeline** - Temporal prediction patterns
6. **Confidence Analysis** - Accuracy stratified by confidence

## 🔬 Research

### Citation

```bibtex
@software{zero_day_llm_ensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent Large Language Model Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```

### Key Findings

- **High Precision**: 80% precision minimizes false positives
- **Conservative Approach**: Favors reliability over detection rate
- **No Data Leakage**: Operates without source labels or timestamps
- **Robust Performance**: Consistent across different CVE years and vendors

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

```bash
# Clone and setup
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
python -m venv venv
source venv/bin/activate
pip install -e .

# Run tests
python -m pytest tests/
```

## 📫 Support

- **Issues**: [GitHub Issues](https://github.com/lodetomasi/zero-day-llm-ensemble/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lodetomasi/zero-day-llm-ensemble/discussions)
- **Email**: lorenzo.detomasi@graduate.univaq.it

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [CISA](https://www.cisa.gov/) for the Known Exploited Vulnerabilities catalog
- [NVD](https://nvd.nist.gov/) for the comprehensive vulnerability database
- [OpenRouter](https://openrouter.ai/) for unified LLM API access
- University of L'Aquila for research support

---

<p align="center">
  <sub>Built with ❤️ at University of L'Aquila</sub>
</p>