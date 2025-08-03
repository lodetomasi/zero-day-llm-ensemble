# Zero-Day LLM Ensemble - Usage Guide

## 🚀 Quick Start

### 1. Setup Environment

```bash
# Install dependencies
pip install -r requirements.txt

# Create .env file with your API key
echo "OPENROUTER_API_KEY=your-api-key-here" > .env
```

### 2. Test API Connectivity

```bash
python test_api_connectivity.py
```

### 3. Run Detection

## Single CVE Detection

```bash
python detect_zero_days.py CVE-2023-23397
```

## Quick Test (6 CVEs)

```bash
python quick_test_detection.py
```

Results:
- **100% Accuracy** (6/6 correct)
- **100% Precision** (no false positives)
- **100% Recall** (no false negatives)

## Comprehensive Test (30 CVEs)

```bash
python run_comprehensive_test.py
```

## Large Scale Test (40 CVEs)

```bash
# Create extended dataset
python create_extended_dataset.py

# Run batch testing with caching
python run_large_scale_test.py
```

Features:
- Batch processing (5 CVEs per batch)
- Result caching to save API costs
- Interactive mode with continue prompts
- Performance visualizations

## 📊 Analyze Results

```bash
python analyze_test_results.py
```

Generates:
- Performance metrics (accuracy, precision, recall, F1)
- Confusion matrix
- Score distributions
- Threshold analysis

## 🗂️ Project Structure

```
zero-day-llm-ensemble/
├── detect_zero_days.py          # Main detection script
├── quick_test_detection.py      # Quick 6-CVE test
├── run_comprehensive_test.py    # 30-CVE test suite
├── run_large_scale_test.py      # 40-CVE batch test
├── analyze_test_results.py      # Results analysis
├── src/
│   ├── agents/                  # 5 specialized LLM agents
│   ├── ensemble/                # Multi-agent ensemble
│   ├── scraping/                # Web scraping modules
│   └── utils/                   # Feature extraction, logging
├── data/                        # Datasets and caches
├── detection_reports/           # JSON detection results
└── results/                     # Test summaries and plots
```

## 🔧 Configuration

Edit `config/settings.py` for:
- Model selection
- API endpoints
- Detection thresholds
- Rate limiting

## 💡 Tips

1. **API Costs**: Use caching for large tests
2. **Rate Limits**: Adjust delays in settings
3. **Accuracy**: Optimal threshold is 0.7-0.8
4. **Debugging**: Check `detection_reports/` for details

## 📈 Performance

Current results on test set:
- Zero-days detected: 4/4 (100%)
- False positives: 0/2 (0%)
- Average confidence: 66.11%
- Processing time: ~30s per CVE