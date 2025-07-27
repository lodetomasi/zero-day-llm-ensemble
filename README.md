# Zero-Day Vulnerability Detection Using Web Evidence and LLM Ensemble

## Overview

This system detects zero-day vulnerabilities using a unified approach that combines web evidence collection with multi-agent LLM analysis. It achieves **83.3% accuracy** through:
- **Web Scraping**: Collects evidence from 8 authoritative sources
- **Evidence-Enriched LLM Analysis**: 5 specialized AI agents analyze CVEs with full web evidence context
- **Single Decision Flow**: Web evidence → LLM agents → Final classification

### Key Innovation
The system now passes web-scraped evidence directly to LLM agents, improving their classification accuracy from 44% to 80%+ by providing critical context like CISA KEV status, APT associations, and exploitation indicators.

## Quick Start

### Installation
```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
```

### Set API Key
```bash
export OPENROUTER_API_KEY="your-api-key-here"
```

### Run Analysis
```bash
# Analyze specific CVEs (recommended)
python analyze_cve.py CVE-2023-23397 CVE-2021-44228 --verbose

# Quick test
python analyze_cve.py CVE-2023-23397 -v

# Multiple CVEs
python analyze_cve.py CVE-2023-23397 CVE-2021-44228 CVE-2024-3400
```

## How It Works

### 1. Web Evidence Collection
The system scrapes 8 sources for each CVE:
- **CISA KEV**: Known exploited vulnerabilities database
- **Security News**: The Hacker News, BleepingComputer, SecurityWeek
- **GitHub**: Proof-of-concept repositories
- **Threat Intelligence**: APT group associations
- **Vendor Advisories**: Emergency patches, out-of-band updates
- **Social Media**: Security researcher discussions
- **Exploit Databases**: Metasploit, Exploit-DB
- **NVD**: Official CVE details

### 2. LLM Ensemble Analysis
Five specialized agents analyze each CVE **enriched with web evidence**:

| Agent | Model | Focus Area |
|-------|-------|------------|
| **ForensicAnalyst** | Mixtral-8x22B | Exploitation indicators |
| **PatternDetector** | Claude 3 Opus | Linguistic patterns |
| **TemporalAnalyst** | Llama 3.3 70B | Timeline analysis |
| **AttributionExpert** | DeepSeek R1 | Threat actor behavior |
| **MetaAnalyst** | Gemini 2.5 Pro | Holistic synthesis |

**Evidence Enhancement**: LLMs now receive:
- CISA KEV listing status
- Security news mentions of zero-day exploitation
- APT group associations
- GitHub PoC availability and timeline
- Emergency/out-of-band patch indicators
- Threat intelligence from multiple sources

### 3. Final Classification
```
Flow: Web Evidence → Passed to LLM Agents → Final Score
Classification: Zero-day if LLM Score ≥ 0.5
```

## System Architecture

```mermaid
graph LR
    subgraph "Input"
        CVE[CVE ID]
    end
    
    subgraph "Evidence Collection"
        CVE --> Web[Web Scraping<br/>8 Sources]
        Web --> Evidence[Evidence Context]
    end
    
    subgraph "Analysis"
        Evidence --> |Full Context| LLM[LLM Ensemble<br/>5 Agents]
        CVE --> LLM
        LLM --> Score[Final Score]
    end
    
    subgraph "Decision"
        Score --> Thresh{Score ≥ 0.5?}
        Thresh -->|Yes| ZD[Zero-Day]
        Thresh -->|No| Reg[Regular CVE]
    end
    
    style Web fill:#dae8fc
    style LLM fill:#e1d5e7
    style Score fill:#fff2cc
    style ZD fill:#d5e8d4
```

## Performance

### Enhanced System Results (with Evidence-Enriched LLMs)

| Metric | Value | Improvement |
|--------|-------|-------------|
| **Accuracy** | 83.3% | +88.6% from baseline |
| **Precision** | 75.0% | Low false positives |
| **Recall** | 100.0% | Detected all zero-days |
| **F1-Score** | 0.857 | Excellent balance |

### Performance Comparison

| System Configuration | Accuracy | Notes |
|---------------------|----------|-------|
| LLM-only (no evidence) | 44.0% | Baseline without web scraping |
| LLM + Web Evidence | 83.3% | Full system with evidence-enriched LLMs |

### Confusion Matrix
```
              Predicted
           Zero-day  Regular
Actual  
Zero-day       3        0
Regular        1        2
```

## Evidence Scoring Algorithm

```python
evidence_score = 0.0

# High-value indicators
if in_cisa_kev: 
    evidence_score += 0.3
    
if apt_associations:
    evidence_score += 0.15
    
if emergency_patches:
    evidence_score += 0.1
    
if vendor_out_of_band_update:
    evidence_score += 0.15
    
# Additional indicators
if zero_day_mentions_in_news > 0:
    evidence_score += 0.1 * min(mentions, 3)
    
if github_poc_before_patch:
    evidence_score += 0.1
    
if exploit_db_entry:
    evidence_score += 0.05
```

## Output Files

- `results/analysis_report_*.json` - Complete analysis with evidence and scores
- `results/analysis_summary_*.md` - Human-readable summary
- `reports/CVE-*_report_*.json` - Individual CVE reports
- `data/scraping_cache/` - 7-day cache for web scraping

## Example Output

```
🚀 Zero-Day Detection System
============================================================
Analyzing CVE-2023-23397

📡 Step 1: Collecting web evidence...
  ✓ Evidence collected from 8 sources
  📌 Found in CISA Known Exploited Vulnerabilities
  📌 Associated with APT groups: FOREST BLIZZARD
  📌 Found 12 proof-of-concept repositories

🤖 Step 2: Analyzing with LLM ensemble (with web evidence)...
  📄 Evidence context passed to LLMs:
    - ⚠️ LISTED IN CISA KNOWN EXPLOITED VULNERABILITIES
    - 📰 Found 5 security articles mentioning zero-day exploitation
    - 🎯 Associated with APT groups: FOREST BLIZZARD
    - 💻 Found 12 proof-of-concept repositories
  
🎯 FINAL VERDICT: ZERO-DAY
   Score: 85.0% (confidence: 78.0%)
```

## Advanced Usage

### Batch Processing
```bash
# Analyze multiple CVEs at once
python analyze_cve.py CVE-2023-23397 CVE-2023-20198 CVE-2024-3400 CVE-2021-44228 CVE-2014-0160

# With verbose output
python analyze_cve.py CVE-2023-23397 CVE-2023-20198 CVE-2024-3400 --verbose
```

### Using Pre-collected Dataset
```bash
# For reproducible testing
python run_test_from_dataset.py --zero-days 25 --regular 25

# Enable parallel execution for faster results
python run_test_from_dataset.py --zero-days 10 --regular 10 --parallel
```

### Key Improvements in Latest Version
1. **Evidence-Enriched LLMs**: Web evidence is now passed directly to LLM agents
2. **Bias Removal**: Fixed hardcoded source-based predictions 
3. **Better Context**: LLMs receive CISA KEV status, APT associations, and more
4. **Improved Accuracy**: From 44% to 80%+ by providing evidence to LLMs

## Requirements

- Python 3.8+
- OpenRouter API key
- Dependencies in requirements.txt

## Citation

```bibtex
@software{zero_day_detection_enhanced,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Detection Using Web Evidence and LLM Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```

## License

MIT License - see LICENSE file for details.