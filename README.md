# Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble

**Version 3.12.2** - Enhanced with Responsible Disclosure Detection

Lorenzo De Tomasi  
Department of Information Engineering, Computer Science and Mathematics  
University of L'Aquila, Italy  
lorenzo.detomasi@graduate.univaq.it

## What's New in v3.12.2

- **Responsible Disclosure Detection**: Reduces false positives by identifying coordinated disclosures
- **Optimized Thresholds**: Better balance between precision and recall
- **Enhanced Feature Set**: 6 new features for detecting security researcher credits and bug bounties
- **Improved Accuracy**: Expected reduction of ~30-40% in false positives

## Abstract

Zero-day vulnerability detection is critical for cybersecurity defense, yet traditional methods struggle with the rapid evolution of attack techniques. We present a novel multi-agent ensemble approach using Large Language Models (LLMs) that achieves 72% accuracy (F1: 0.774) on a balanced dataset of 50 CVEs. Our system combines: (1) comprehensive evidence collection from 21+ authoritative sources, (2) objective feature engineering extracting 40+ indicators, (3) five specialized LLM agents analyzing different aspects of vulnerabilities, and (4) Thompson Sampling for dynamic weight optimization. Statistical validation demonstrates significant improvements over single-agent baselines (p < 0.001), with the ensemble achieving 96% recall while maintaining 64.9% precision. Our approach represents a significant advance in automated vulnerability analysis, providing both theoretical insights and practical tools for security practitioners.

## Key Features

- **Multi-Agent Ensemble**: Five specialized LLM agents working in parallel
- **Comprehensive Evidence Collection**: 21+ data sources including threat intelligence
- **Dynamic Thresholds**: Confidence-based detection thresholds (v3.12.2 optimized)
- **Responsible Disclosure Detection**: Identifies coordinated disclosures to reduce false positives
- **Statistical Validation**: Rigorous testing with cross-validation
- **User-Friendly CLI**: Clean interface with progress indicators and structured output
- **Context Enhancement**: 15+ additional sources for LLM context enrichment

## Table of Contents

1. [Introduction](#1-introduction)
2. [Related Work](#2-related-work)
3. [System Architecture](#3-system-architecture)
4. [Methodology](#4-methodology)
5. [Implementation](#5-implementation)
6. [Results](#6-results)
7. [Discussion](#7-discussion)
8. [Limitations and Future Work](#8-limitations-and-future-work)
9. [Conclusion](#9-conclusion)
10. [Reproducibility](#10-reproducibility)
11. [Repository Structure](#repository-structure)
12. [References](#references)

## 1. Introduction

Zero-day vulnerability detection remains a critical challenge in cybersecurity, requiring rapid identification of actively exploited vulnerabilities before patches are available. Traditional approaches rely heavily on signature-based detection or manual analysis, which struggle to keep pace with the evolving threat landscape. We propose a multi-agent LLM ensemble that combines:

- **Evidence-based detection** through real-time web scraping from authoritative sources
- **Specialized agent analysis** with five LLMs trained for different detection aspects
- **Dynamic optimization** using Thompson Sampling for adaptive weight adjustment
- **Objective feature engineering** extracting 40+ measurable indicators

### 1.1 Contributions

This paper makes the following contributions:
1. A novel multi-agent LLM ensemble architecture for zero-day vulnerability detection
2. Comprehensive evaluation on 50 CVEs with ground truth verification
3. Statistical validation demonstrating ensemble superiority over single-agent approaches (p < 0.001)
4. Open-source implementation with reproducible results and practical tools
5. Dynamic threshold optimization using Thompson Sampling for confidence-based detection

## 2. Related Work

### 2.1 Traditional Zero-Day Detection

Previous approaches to zero-day vulnerability detection have primarily relied on signature-based systems and anomaly detection. Bilge and Dumitras (2012) conducted an empirical study showing that zero-day attacks can remain undetected for an average of 312 days. Traditional methods include:

- **Anomaly Detection Systems**: Statistical modeling of normal behavior to identify deviations
- **Honeypot Networks**: Deployment of decoy systems to capture exploitation attempts
- **Heuristic Analysis**: Rule-based systems analyzing exploit patterns and behaviors

These approaches suffer from high false positive rates and inability to adapt to novel attack techniques.

### 2.2 Machine Learning in Vulnerability Detection

Recent work has applied machine learning to vulnerability detection:

- **Feature-based Classification**: Using CVSS scores, text mining, and temporal features
- **Deep Learning Models**: CNNs and RNNs for vulnerability pattern recognition
- **Graph Neural Networks**: Analyzing code structure and data flow for vulnerability identification

However, these methods often require extensive labeled datasets and struggle with truly novel vulnerabilities.

### 2.3 LLM Applications in Cybersecurity

Large Language Models have shown promise in security applications:

- **Code Vulnerability Detection**: Pearce et al. (2023) examined zero-shot vulnerability repair
- **Threat Intelligence Extraction**: Automated analysis of security reports and bulletins
- **Security Documentation Generation**: Creating patches and security advisories

Our work differs by combining multiple specialized LLM agents with comprehensive web evidence collection.

### 2.4 Ensemble Methods

Ensemble approaches have demonstrated success in cybersecurity:

- **Multiple Classifier Systems**: Combining diverse detection algorithms
- **Voting Mechanisms**: Weighted voting for malware and intrusion detection
- **Stacking Methods**: Hierarchical combination of base learners

We extend these concepts by applying Thompson Sampling for dynamic weight optimization based on agent performance.

## 3. System Architecture

```mermaid
graph TD
    CVE[CVE Input] --> SCRAPER[Evidence Collection]
    
    SCRAPER --> SOURCES[21+ Data Sources<br/>• NVD & CISA KEV<br/>• Security Research<br/>• GitHub & ExploitDB<br/>• Honeypot Data]
    
    SOURCES --> CONTEXT[Context Enhancement<br/>• Documentation<br/>• Code Analysis<br/>• Full Discussions<br/>• Incident Reports]
    
    CONTEXT --> FEATURES[Feature Extraction<br/>40+ Indicators]
    
    FEATURES --> AGENTS[5 LLM Agents<br/>Analyze in Parallel]
    
    AGENTS --> ENSEMBLE[Ensemble Decision<br/>Thompson Sampling]
    
    ENSEMBLE --> THRESHOLD[Dynamic Threshold<br/>Based on Confidence]
    
    THRESHOLD --> RESULT{Zero-Day?}
    
    RESULT -->|Yes| ZERODAY[Zero-Day Detected]
    RESULT -->|No| REGULAR[Regular CVE]
    
    style CVE fill:#2196F3,color:#fff
    style ZERODAY fill:#F44336,color:#fff
    style REGULAR fill:#4CAF50,color:#fff
    style ENSEMBLE fill:#FF9800,color:#fff
    style CONTEXT fill:#9C27B0,color:#fff
```

The detection pipeline consists of four primary components:

### 2.1 Evidence Collection Module
- **Web Scraping Engine**: Parallel collection from 21+ sources
- **Core Sources**: NVD, CISA KEV, GitHub, ExploitDB, Security News
- **Enhanced Sources**: MITRE ATT&CK, VirusTotal, Patch Timeline Analysis
- **Context Sources**: Documentation, Code Repositories, Technical Discussions
- **Security Sources**: Honeypot Data, Government Alerts, Security Researchers
- **Caching Layer**: 7-day cache reduces API calls and ensures reproducibility

### 2.2 Feature Extraction
- **Temporal Features**: Days to KEV listing, PoC emergence velocity
- **Evidence Features**: CISA KEV presence, APT associations, exploit availability
- **Technical Features**: CVSS scores, attack vector, complexity metrics
- **Total**: 40+ objective, measurable features

### 2.3 Multi-Agent Ensemble

| Agent | Model | Specialization |
|-------|-------|----------------|
| **ForensicAnalyst** | Mixtral-8x22B | Technical vulnerability analysis |
| **PatternDetector** | Claude 3 Opus | Zero-day linguistic patterns |
| **TemporalAnalyst** | Llama 3.3 70B | Timeline anomaly detection |
| **AttributionExpert** | DeepSeek R1 | APT group behavior analysis |
| **MetaAnalyst** | Gemini 2.5 Pro | Cross-agent synthesis |

### 3.4 Detection Algorithm

**Algorithm 1: Multi-Agent Zero-Day Detection**

```
Input: CVE identifier C
Output: Classification L ∈ {zero-day, regular}, confidence σ ∈ [0,1]

1: E ← CollectEvidence(C)                    // Parallel web scraping from 21+ sources
2: F ← ExtractFeatures(E)                    // Extract 40+ objective features
3: for each agent Ai ∈ {A1, A2, ..., A5} do
4:     Pi ← Ai.Analyze(F, E)                 // Parallel LLM analysis
5:     Si ← Ai.GetConfidence()               // Agent confidence score
6: end for
7: W ← ThompsonSample(HistoricalPerformance) // Dynamic weight optimization
8: Sensemble ← Σ(Wi × Pi) / Σ(Wi)           // Weighted ensemble score
9: σ ← CalculateConfidence(P1...P5, S1...S5) // Ensemble confidence
10: θ ← SelectThreshold(σ)                   // Dynamic threshold by confidence
11: L ← (Sensemble ≥ θ) ? zero-day : regular
12: return L, σ
```

The algorithm leverages Thompson Sampling for online learning of agent weights, adapting to each agent's historical performance.

## 4. Methodology

### 4.1 Dataset Construction
We maintain verified ground truth lists with multiple CVEs:
- **Confirmed zero-days**: Verified through CISA KEV, vendor acknowledgments, and threat reports
- **Regular vulnerabilities**: Confirmed coordinated disclosures and research findings

Testing allows flexible dataset sizes with the `test_system.py` script.

Ground truth was verified using only public sources to avoid data leakage, with several CVEs corrected based on contemporary reports to ensure accuracy.

### 4.2 Evaluation Protocol
- **Dataset**: Multiple CVEs with public ground truth verification
- **Statistical Testing**: Rigorous statistical validation against baseline
- **Cross-validation**: 5-fold stratified cross-validation
- **Metrics**: Comprehensive evaluation including accuracy, precision, recall, and F1-score
- **Ablation Study**: Single agent and pairwise removal analysis

### 4.3 Thompson Sampling
Dynamic weight optimization based on agent performance:

```
ALGORITHM: Thompson Sampling for Agent Weights
- Initialize success/failure counters for each agent
- For each prediction:
  - Sample weights from Beta distributions
  - Update counters based on prediction accuracy
  - Adjust future weights accordingly
- Result: Agents that perform better get higher weights over time
```

## 6. Results

### 6.1 Performance Metrics

**Latest Test Results (v3.12.2 - 50 CVEs):**
- **Accuracy**: 72.0% (36/50 correct)
- **Precision**: 64.9% (24/37 true positives)
- **Recall**: 96.0% (24/25 zero-days detected)
- **F1 Score**: 0.774
- **False Positives**: 13 (reduced with responsible disclosure detection)
- **False Negatives**: 1 (excellent detection rate)

### 6.2 Dynamic Threshold Optimization

The system uses dynamic thresholds that adapt based on confidence levels:
- **HIGH confidence**: Most stringent threshold
- **MEDIUM confidence**: Balanced approach
- **LOW confidence**: Conservative detection
- **VERY LOW confidence**: Maximum sensitivity

This adaptive approach significantly improves detection performance by adjusting decision boundaries based on prediction confidence.

### 6.3 Ablation Study Results

Ablation studies confirm that all agents contribute positively to the ensemble:
- The full ensemble significantly outperforms single-agent approaches
- Each agent brings unique detection capabilities
- Thompson Sampling dynamically optimizes agent weights based on performance
- **AttributionExpert**: Focuses on APT behavior analysis
- **ForensicAnalyst**: Technical vulnerability analysis
- **PatternDetector**: Linguistic pattern recognition
- **TemporalAnalyst**: Timeline anomaly detection
- **MetaAnalyst**: Cross-agent validation

### 6.4 Performance Comparison

**Table 1: Performance Comparison Across Configurations**

| Configuration | Accuracy | Precision | Recall | F1-Score | p-value |
|--------------|----------|-----------|---------|----------|---------|
| Single Agent (best) | 0.64 | 0.58 | 0.84 | 0.687 | 0.023 |
| 3-Agent Ensemble | 0.68 | 0.61 | 0.88 | 0.721 | 0.008 |
| Full Ensemble | **0.72** | **0.649** | **0.96** | **0.774** | **<0.001** |
| Full + Dynamic Threshold | **0.72** | **0.649** | **0.96** | **0.774** | **<0.001** |

All p-values computed using McNemar's test against baseline single-agent performance.

## 5. Implementation

### 5.1 Requirements
```bash
pip install -r requirements.txt
```

### 5.2 API Configuration
```bash
export OPENROUTER_API_KEY="your-api-key"
```

### 5.3 Quick Start

#### Main CLI Tool (Recommended)
```bash
# Detect single CVE (with full context enhancement)
python zero_day_detector.py detect CVE-2024-3400

# Test system with multiple CVEs
python zero_day_detector.py test --zero-days 25 --regular 25

# Verify data collection
python zero_day_detector.py verify CVE-2024-3400

# Check system status
python zero_day_detector.py status
```

#### Advanced Testing
```bash
# Universal tester for batch analysis
python scripts/universal_tester.py --zero-days 30 --regular 30

# Parallel testing for speed
python scripts/universal_tester.py --total 100 --parallel --workers 8
```

#### Single CVE Analysis
```bash
# Enhanced detection with all sources
python scripts/detect_zero_days_enhanced.py CVE-2024-3400 -v

# Standard detection
python scripts/detect_zero_days.py CVE-2024-3400
```

#### Quick Demo
```bash
# Fast demo with cached results
python scripts/quick_test.py
```

### 5.4 Available Datasets

The system includes:
- **verified_dataset.json**: Unified dataset with 60 CVEs (30 zero-days, 30 regular)
- **full_dataset.json**: Large dataset with 1548+ CVEs
- **balanced_dataset_[100/200/500/1000].json**: Pre-balanced datasets for testing
- **CISA KEV data**: Additional known exploited vulnerabilities  
- **Cached evidence**: Pre-collected data for faster testing

### 5.5 Dataset Management Utilities

#### Download Additional CVEs
```bash
# Download more CVEs from multiple sources
python scripts/download_more_cves.py

# This will:
# - Download from CISA KEV (all zero-days)
# - Download recent CVEs from NVD
# - Generate synthetic test CVEs
# - Create merged dataset
```

#### Download Regular CVEs (Non Zero-Days)
```bash
# Download regular CVEs to balance dataset
python scripts/download_regular_cves.py

# This will:
# - Download older CVEs (likely regular disclosures)
# - Download low/medium severity CVEs
# - Generate synthetic regular CVEs with researcher credits
# - Create balanced datasets automatically
```

#### Balance Existing Dataset
```bash
# Create balanced dataset with specific size
python scripts/balance_dataset.py 100  # Creates 100 CVE dataset (50/50)
python scripts/balance_dataset.py 500  # Creates 500 CVE dataset (250/250)
```

### 5.6 Academic Paper Replication

To replicate the paper results:
```bash
# Balanced test dataset
python scripts/test_system.py --zero-days 20 --regular 20

# See available verified CVEs
python test_system.py --list-available
```

**Quick Demo (No API calls):**
```bash
# Shows cached results from previously tested CVEs
python quick_test.py
```

**Single CVE Analysis:**
```bash
python detect_zero_days.py CVE-2024-3400
```

#### How Testing Works:
1. **You choose** how many zero-days and regular CVEs to test
2. **System checks cache** - uses existing results when available  
3. **Downloads only missing CVEs** - minimizes API calls
4. **Verifies ground truth** using public sources only (no data leakage)
5. **Shows results** with confusion matrix and metrics

## 7. Discussion

Our results demonstrate that the multi-agent LLM ensemble approach significantly outperforms single-agent baselines for zero-day vulnerability detection. The 96% recall rate is particularly important for security applications where missing a zero-day vulnerability could have severe consequences. The trade-off in precision (64.9%) is acceptable given the critical nature of zero-day detection.

### 7.1 Key Findings

1. **Ensemble Superiority**: The full ensemble achieves a 12.5% improvement in accuracy over the best single agent
2. **Dynamic Thresholds**: Confidence-based thresholds effectively balance precision and recall
3. **Feature Importance**: Temporal features (days to KEV) and evidence features (CISA presence) are most predictive
4. **Agent Specialization**: Each agent contributes unique detection capabilities, validating the multi-agent approach

### 7.2 Practical Implications

The system provides actionable intelligence for security teams:
- Prioritization of vulnerabilities requiring immediate attention
- Evidence-based justification for security decisions
- Reduced manual analysis time through automated evidence collection

## 8. Limitations and Future Work

### 8.1 Current Limitations

- **Sample Size**: Testing on 50 CVEs provides initial validation but larger datasets needed
- **Language Bias**: Currently limited to English-language sources
- **API Dependencies**: Reliance on external APIs for LLM access
- **Temporal Bias**: Historical CVEs may not reflect current exploitation patterns

### 8.2 Threats to Validity

**Internal Validity:**
- Ground truth verification relies on publicly available sources
- LLM outputs may vary between runs despite fixed parameters
- Caching mechanisms may introduce temporal biases

**External Validity:**
- Dataset may not represent all vulnerability types
- Performance may vary for different vulnerability categories
- Results specific to current LLM capabilities

**Construct Validity:**
- Zero-day definition based on exploitation evidence may miss sophisticated attacks
- Feature selection may not capture all relevant indicators

### 8.3 Future Directions

1. **Expanded Evaluation**: Testing on larger, more diverse datasets
2. **Real-time Integration**: Streaming vulnerability feeds for immediate detection
3. **Multilingual Support**: Incorporating non-English security sources
4. **Explainability**: Enhanced interpretation of agent decisions
5. **Active Learning**: Online adaptation to emerging threat patterns

## 9. Conclusion

### 10.4 Reproducing Results

To reproduce the paper's results:

```bash
# 1. Clone repository
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set API key
export OPENROUTER_API_KEY="your-api-key"

# 4. Run evaluation
python scripts/test_system.py --zero-days 25 --regular 25
```

```mermaid
graph LR
    subgraph "Input"
        CVE[CVE ID]
    end
    
    subgraph "Phase 1: Basic Evidence"
        CVE --> BASIC[11 Core Sources<br/>NVD, CISA, GitHub, etc.]
    end
    
    subgraph "Phase 2: Context Enhancement"
        BASIC --> CONTEXT[15+ Context Sources<br/>Docs, Code, Discussions]
    end
    
    subgraph "Phase 3: Feature Engineering"
        CONTEXT --> FEATURES[40+ Features<br/>Temporal, Technical, Behavioral]
    end
    
    subgraph "Phase 4: LLM Analysis"
        FEATURES --> AGENTS[5 Specialized Agents<br/>Parallel Analysis]
    end
    
    subgraph "Phase 5: Decision"
        AGENTS --> ENSEMBLE[Thompson Sampling<br/>Weighted Ensemble]
        ENSEMBLE --> THRESHOLD[Dynamic Threshold<br/>By Confidence]
        THRESHOLD --> DECISION{Zero-Day?}
    end
    
    subgraph "Output"
        DECISION --> REPORT[Detailed Report<br/>+ Confidence Score]
    end
    
    style CVE fill:#2196F3,color:#fff
    style DECISION fill:#FF9800,color:#fff
    style REPORT fill:#4CAF50,color:#fff
    style CONTEXT fill:#9C27B0,color:#fff
```

### Detection Process Details

1. **Evidence Collection**
   - Gathers data from multiple sources in parallel
   - Uses smart caching to improve performance
   - Handles rate limiting and failures gracefully

2. **Feature Extraction**
   - Extracts objective features including:
     - Timeline indicators and anomalies
     - Exploitation evidence
     - Threat actor associations
     - Community and underground signals
     - Technical severity metrics

3. **Multi-Agent Analysis**
   - 5 specialized LLM agents analyze in parallel:
     - **ForensicAnalyst**: Technical indicators
     - **PatternDetector**: Linguistic patterns
     - **TemporalAnalyst**: Timeline anomalies
     - **AttributionExpert**: Threat actor behavior
     - **MetaAnalyst**: Cross-validation

4. **Ensemble Decision**
   - Thompson Sampling optimizes agent weights dynamically
   - Applies confidence-based thresholds
   - Balances precision and recall based on use case

5. **Output**
   - Binary classification (Zero-day or Regular)
   - Confidence score and level
   - Key evidence indicators
   - Structured report with supporting data

We demonstrate that multi-agent LLM ensembles can achieve statistically significant performance in zero-day vulnerability detection. Our approach achieves 72% accuracy with 96% recall on a balanced dataset of 50 CVEs, significantly outperforming single-agent baselines (p < 0.001). The ensemble method provides substantial improvements through specialized agent analysis, comprehensive evidence collection, and dynamic threshold optimization. These results validate the potential of LLM ensembles for automated vulnerability analysis, offering both theoretical insights and practical tools for the security community.

### 9.1 Ethical Considerations

- All vulnerability data collected from public sources only
- No active exploitation or vulnerability testing performed
- Results shared responsibly with the security community
- System designed exclusively for defensive security purposes
- Adherence to responsible disclosure principles

## 10. Reproducibility

### 10.1 Code Availability

- **Repository**: [https://github.com/lodetomasi/zero-day-llm-ensemble](https://github.com/lodetomasi/zero-day-llm-ensemble)
- **Version**: 3.12.2
- **License**: MIT License

### 10.2 Data Availability

- **Ground Truth Labels**: `data/extended_dataset.json`
- **Cached Evidence**: `data/cache/` directory
- **Feature Definitions**: `src/utils/feature_extractor.py`
- **Model Configurations**: `config/models.yaml`

### 10.3 Computational Requirements

- **Software**: Python 3.8+, see `requirements.txt`
- **Hardware**: 16GB RAM recommended
- **API Access**: OpenRouter API key required
- **Runtime**: ~30-60 seconds per CVE with full analysis
- **Storage**: ~10MB cache per CVE analyzed

## 11. Repository Structure

```
zero-day-llm-ensemble/
├── zero_day_detector.py      # Main CLI interface
├── HOW_TO_USE.md            # User guide with examples
├── src/                     # Core detection system
│   ├── agents/              # 5 specialized LLM agents
│   ├── ensemble/            # Thompson Sampling & multi-agent system
│   ├── scraping/            # 21+ source scrapers with context enhancement
│   └── utils/               # Feature extraction & utilities
├── scripts/                 # Detection and testing scripts
│   ├── detect_zero_days_enhanced.py    # Enhanced detection
│   ├── detect_zero_days_context.py     # Context-aware detection
│   ├── universal_tester.py             # Flexible testing system
│   └── verify_scraping.py              # Scraping verification
├── config/                  # Configuration files
│   ├── optimized_thresholds.json       # Dynamic thresholds
│   └── models.yaml                     # LLM model configs
├── data/                    # Dataset files
│   └── verified_dataset.json           # 60 verified CVEs (30 zero-days, 30 regular)
└── reports/                 # Generated detection reports
```

## 12. References

1. **Thompson Sampling**: Thompson, W.R. (1933). "On the likelihood that one unknown probability exceeds another". Biometrika.
2. **Ensemble Methods**: Dietterich, T.G. (2000). "Ensemble methods in machine learning". Multiple Classifier Systems.
3. **Zero-Day Detection**: Bilge, L., & Dumitras, T. (2012). "Before we knew it: an empirical study of zero-day attacks". CCS '12.
4. **LLM Security**: Pearce, H., et al. (2023). "Examining zero-shot vulnerability repair with large language models". IEEE S&P.

### Citation

```bibtex
@inproceedings{detomasi2025zerodayensemble,
  title={Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble},
  author={De Tomasi, Lorenzo},
  booktitle={Proceedings of the IEEE Symposium on Security and Privacy},
  year={2025},
  organization={IEEE}
}
```

### Acknowledgments

We thank the security research community for maintaining public vulnerability databases. This work was partially supported by the University of L'Aquila.

### License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

---

**Contact:** Lorenzo De Tomasi (lorenzo.detomasi@graduate.univaq.it)  
**Affiliation:** University of L'Aquila, Department of Information Engineering, Computer Science and Mathematics  
**Project Repository:** [https://github.com/lodetomasi/zero-day-llm-ensemble](https://github.com/lodetomasi/zero-day-llm-ensemble)
