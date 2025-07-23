# Zero-Day LLM Ensemble

A sophisticated zero-day vulnerability detection system using an ensemble of specialized LLMs without data leakage.

## 🎯 Key Features

- **5 Specialized LLM Agents**: Multi-perspective vulnerability analysis
- **Zero Data Leakage**: Classification based solely on CVE content
- **Open-Ended Prompts**: Models reason freely without hardcoded patterns
- **Automatic Visualizations**: 6 performance charts generated automatically
- **Real-time Monitoring**: Live statistics during execution

## 📊 Performance

On balanced dataset (50 CVEs: 25 zero-day, 25 regular):

- **Accuracy**: ~70%
- **Precision**: ~80% (low false positive rate)
- **Recall**: ~45% (identifies nearly half of zero-days)
- **Zero false positives** on regular CVEs in many tests

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# Install dependencies
pip install -r requirements.txt

# Set OpenRouter API key
export OPENROUTER_API_KEY="your-api-key"
```

### 2. Run Tests

```bash
# Quick test (20 CVEs, ~5 minutes)
python run_complete_test.py --zero-days 10 --regular 10 --parallel

# Medium test (50 CVEs, ~15 minutes) 
python run_complete_test.py --zero-days 25 --regular 25 --parallel

# Full test (100 CVEs, ~30 minutes)
python run_complete_test.py --zero-days 50 --regular 50 --parallel
```

### 3. Results

Results are saved in:
- `results/complete_test_TIMESTAMP.json` - Complete data
- `results/analysis_plots_TIMESTAMP.png` - 6 analysis charts
- `results/report_TIMESTAMP.txt` - Text report

## 🤖 LLM Agents

| Agent | Model | Specialization |
|-------|-------|----------------|
| ForensicAnalyst | Mixtral-8x22B | Forensic analysis and exploitation indicators |
| PatternDetector | Claude Opus 4 | Linguistic and technical pattern recognition |
| TemporalAnalyst | Llama 3.3 70B | Timeline analysis and urgency detection |
| AttributionExpert | DeepSeek R1 | Threat actor and targeting assessment |
| MetaAnalyst | Gemini 2.5 Pro | Synthesis and final decision |

## 📈 Generated Visualizations

1. **Confusion Matrix** - Shows TP/FP/TN/FN
2. **Performance Metrics** - Bar chart with Accuracy, Precision, Recall, F1
3. **Score Distribution** - Histogram of probabilities by class
4. **ROC Curve** - Trade-off between TPR and FPR
5. **Prediction Timeline** - Prediction trends over time
6. **Accuracy by Confidence** - Performance by confidence level

## 🔧 Architecture

```
zero-day-llm-ensemble/
├── src/
│   ├── agents/          # 5 LLM agent implementations
│   ├── data/            # Data collection from CISA KEV and NVD
│   ├── ensemble/        # Multi-agent system and voting
│   └── utils/           # Logger and utilities
├── config/
│   ├── prompts.yaml     # Open-ended prompts for agents
│   └── settings.py      # Model and API configuration
├── run_complete_test.py # Main script with visualizations
├── run_balanced_test.py # Guaranteed balanced testing
└── results/             # Output directory (gitignored)
```

## 💡 How It Works

1. **Data Collection**: Fetches from CISA KEV (confirmed zero-days) and NVD (regular CVEs)
2. **Preprocessing**: Validation and data preparation without leakage
3. **Multi-Agent Analysis**: Each agent analyzes the CVE from its perspective
4. **Ensemble Voting**: Weighted average of predictions (equal weights)
5. **Classification**: 0.5 threshold to distinguish zero-day from regular

## 🛠️ Configuration

### Change LLM Models

Edit `config/settings.py`:

```python
MODEL_CONFIGS = {
    'ForensicAnalyst': 'mistralai/mixtral-8x22b-instruct',
    'PatternDetector': 'anthropic/claude-opus-4',
    # ... other models
}
```

### Modify Prompts

Prompts are in `config/prompts.yaml`. Use open-ended prompts that allow models to reason freely.

## 📝 Example Usage

```python
from src.ensemble.multi_agent import MultiAgentSystem
from src.data.preprocessor import DataPreprocessor

# Initialize
system = MultiAgentSystem(parallel_execution=True)
preprocessor = DataPreprocessor()

# Analyze a CVE
cve_data = {
    'cve_id': 'CVE-2024-1234',
    'vendor': 'Microsoft',
    'product': 'Windows',
    'description': 'Remote code execution vulnerability...',
    'year': 2024
}

# Preprocess and analyze
processed = preprocessor.preprocess_entry(cve_data)
result = system.analyze_vulnerability(processed)

# Result
prediction = result['ensemble']['prediction']
print(f"Zero-day probability: {prediction:.1%}")
```

## ⚠️ Important Notes

- **No Data Leakage**: Prompts never mention data sources
- **Free Reasoning**: Models don't search for specific hardcoded patterns
- **API Key Required**: OpenRouter API key is necessary
- **Local Cache**: Data is cached to reduce API calls

## 🏆 Key Strengths

1. **High Precision**: When it identifies a zero-day, it's rarely wrong
2. **Zero Bias**: No source references in prompts
3. **Scalable**: Supports parallel agent execution
4. **Transparent**: Detailed logs for every prediction

## 📄 License

MIT License

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🙏 Acknowledgments

- CISA for the Known Exploited Vulnerabilities catalog
- NVD for the National Vulnerability Database
- OpenRouter for LLM model access

## 📊 Research Paper

This system demonstrates that LLMs can effectively identify zero-day vulnerabilities without data leakage by:
- Using open-ended prompts that allow free reasoning
- Avoiding prescriptive pattern matching
- Leveraging ensemble diversity for robust predictions

For detailed methodology and results, see our [technical report](docs/technical_report.pdf) (coming soon).