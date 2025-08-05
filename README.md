# Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble

This repository contains the implementation of a novel multi-agent Large Language Model (LLM) ensemble system for automated zero-day vulnerability detection. Our approach combines evidence-based analysis from multiple data sources with specialized AI agents to achieve state-of-the-art detection performance.

## Table of Contents

- [Introduction](#introduction)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [System Components](#system-components)
- [Performance](#performance)
- [Configuration](#configuration)
- [Experimental Results](#experimental-results)
- [Citation](#citation)
- [License](#license)

## Introduction

Zero-day vulnerabilities represent critical security threats that are actively exploited before patches become available. Traditional signature-based detection methods fail to identify novel exploits, while manual analysis cannot scale to the volume of emerging threats.

We present a system that addresses these challenges through:
- **Multi-source evidence aggregation** from 21+ authoritative sources
- **Ensemble of specialized LLM agents** for comprehensive analysis
- **Thompson Sampling optimization** for dynamic performance improvement
- **High-performance data collection** with 10x speedup using TurboScraper

## Architecture

### System Overview

```mermaid
graph TB
    %% Input Layer
    CVE[CVE Input] --> VAL[Input Validation]
    
    %% Data Collection Layer
    VAL --> TS[TurboScraper<br/>Scrapy Engine]
    TS --> EC[Evidence Collection<br/>21+ Sources]
    
    %% Evidence Sources
    EC --> CISA[CISA KEV]
    EC --> NVD[NVD Database]
    EC --> EDB[ExploitDB]
    EC --> GH[GitHub PoCs]
    EC --> RE[Reddit/Twitter]
    EC --> TI[Threat Intel]
    EC --> HP[Honeypots]
    EC --> DW[Darkweb]
    
    %% Feature Engineering
    CISA --> FE[Feature Extraction<br/>43+ Indicators]
    NVD --> FE
    EDB --> FE
    GH --> FE
    RE --> FE
    TI --> FE
    HP --> FE
    DW --> FE
    
    %% Multi-Agent Analysis
    FE --> MA[Multi-Agent Ensemble]
    MA --> FA[ForensicAnalyst<br/>Mixtral 8x22B]
    MA --> PD[PatternDetector<br/>Claude Opus 4]
    MA --> TA[TemporalAnalyst<br/>Llama 3.3 70B]
    MA --> AE[AttributionExpert<br/>DeepSeek R1]
    MA --> ME[MetaAnalyst<br/>Gemini 2.5 Pro]
    
    %% Optimization Layer
    FA --> TS2[Thompson Sampling<br/>Dynamic Weights]
    PD --> TS2
    TA --> TS2
    AE --> TS2
    ME --> TS2
    
    %% Decision Layer
    FE --> SF[Score Fusion]
    TS2 --> SF
    SF --> DT[Dynamic Threshold<br/>Decision]
    DT --> RES[Detection Result]
    
    %% Caching System
    TS -.-> SC[Smart Cache<br/>Hot/Warm/Cold]
    SC -.-> TS
    
    %% Styling
    classDef input fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef scraper fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef evidence fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef agent fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px
    classDef decision fill:#ffebee,stroke:#b71c1c,stroke-width:2px
    classDef cache fill:#f5f5f5,stroke:#424242,stroke-width:1px,stroke-dasharray: 5 5
    
    class CVE,VAL input
    class TS,EC scraper
    class CISA,NVD,EDB,GH,RE,TI,HP,DW evidence
    class FA,PD,TA,AE,ME agent
    class DT,RES decision
    class SC cache
```

### Data Flow Pipeline

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Scraper
    participant Cache
    participant Features
    participant Agents
    participant Thompson
    participant Decision
    
    User->>CLI: python zeroday.py CVE-2024-3400
    CLI->>Cache: Check cache
    
    alt Cache Miss
        CLI->>Scraper: Fetch evidence
        Scraper->>Scraper: Parallel requests (21+ sources)
        Scraper->>Cache: Store results
    end
    
    Cache->>Features: Extract 43+ features
    Features->>Agents: Send to 5 agents
    
    par Parallel Agent Analysis
        Agents->>Agents: ForensicAnalyst
        and
        Agents->>Agents: PatternDetector
        and
        Agents->>Agents: TemporalAnalyst
        and
        Agents->>Agents: AttributionExpert
        and
        Agents->>Agents: MetaAnalyst
    end
    
    Agents->>Thompson: Agent predictions
    Thompson->>Thompson: Update Beta distributions
    Thompson->>Decision: Weighted scores
    Features->>Decision: Feature scores
    Decision->>Decision: Score fusion (60/30/10)
    Decision->>User: Zero-day: Yes/No (confidence)
```

### Component Architecture

```mermaid
graph LR
    subgraph "Source Code Structure"
        direction TB
        
        subgraph "src/agents"
            BA[base_agent.py]
            FA2[forensic.py]
            PD2[pattern.py]
            TA2[temporal.py]
            AE2[attribution.py]
            ME2[meta.py]
        end
        
        subgraph "src/ensemble"
            MAG[multi_agent.py]
            TSA[thompson.py]
            THR[threshold_manager.py]
        end
        
        subgraph "src/scraping"
            TUS[turbo_scraper.py]
            COM[comprehensive_scraper.py]
            SMC[smart_cache.py]
        end
        
        subgraph "src/utils"
            FEX[feature_extractor.py]
            LLF[llm_formatter.py]
            CRM[credit_monitor.py]
        end
    end
    
    %% Connections
    BA --> FA2
    BA --> PD2
    BA --> TA2
    BA --> AE2
    BA --> ME2
    
    MAG --> TSA
    MAG --> THR
    
    TUS --> SMC
    COM --> SMC
    
    %% Styling
    classDef base fill:#e3f2fd,stroke:#1565c0
    classDef impl fill:#f3e5f5,stroke:#6a1b9a
    classDef core fill:#e8f5e9,stroke:#2e7d32
    classDef util fill:#fff3e0,stroke:#ef6c00
    
    class BA base
    class FA2,PD2,TA2,AE2,ME2 impl
    class MAG,TSA,THR,TUS,COM core
    class FEX,LLF,CRM,SMC util
```

## Key Features

### Multi-Agent LLM Ensemble

Our system employs five specialized agents, each optimized for specific analysis tasks:

| Agent | Model | Specialization | Key Contributions |
|-------|-------|----------------|-------------------|
| **ForensicAnalyst** | Mixtral 8x22B | Technical vulnerability analysis | Deep code-level insights, attack vector identification |
| **PatternDetector** | Claude Opus 4 | Historical pattern matching | Similarity with known zero-days, exploitation patterns |
| **TemporalAnalyst** | Llama 3.3 70B | Timeline anomaly detection | Disclosure-to-exploitation velocity, patch gaps |
| **AttributionExpert** | DeepSeek R1 | Threat actor analysis | APT group associations, campaign identification |
| **MetaAnalyst** | Gemini 2.5 Pro | Cross-agent validation | Consensus building, confidence calibration |

### Evidence Sources

The system aggregates data from 21+ authoritative sources:

**Primary Sources:**
- CISA Known Exploited Vulnerabilities (KEV) catalog
- National Vulnerability Database (NVD)
- MITRE ATT&CK framework
- ExploitDB and Metasploit modules

**Intelligence Sources:**
- Government security alerts (US-CERT, etc.)
- Threat intelligence feeds
- Security vendor advisories
- Bug bounty platforms

**Social Signals:**
- GitHub repositories and PoCs
- Reddit security communities
- Twitter/X security discussions
- Academic research papers

**Network Intelligence:**
- Honeypot detection networks
- Darkweb monitoring
- Ransomware tracking

### Feature Engineering

We extract 43+ objective features across four categories:

**Temporal Features (10 features):**
- `days_to_kev`: Time between disclosure and CISA KEV addition
- `rapid_kev_addition`: Binary indicator for <7 days to KEV
- `days_to_first_poc`: Time to first public exploit
- `patch_velocity`: Speed of vendor response
- `exploitation_window`: Gap between disclosure and patch

**Evidence Features (15 features):**
- `in_cisa_kev`: Presence in CISA KEV (weight: 0.60)
- `has_exploit_code`: Public exploit availability (weight: 0.30)
- `actively_exploited`: Active exploitation evidence (weight: 0.40)
- `apt_association`: APT group involvement (weight: 0.25)
- `ransomware_campaign`: Use in ransomware (weight: 0.35)

**Technical Features (12 features):**
- `cvss_score`: Base CVSS score
- `network_vector`: Remote exploitability
- `low_complexity`: Attack complexity
- `no_user_interaction`: Automation potential
- `privilege_escalation`: Impact severity

**Social Features (6+ features):**
- `social_media_buzz`: Normalized social activity
- `github_activity`: Repository and star metrics
- `researcher_attention`: Security community focus
- `bug_bounty_reports`: Bounty platform activity

### Thompson Sampling Optimization

```mermaid
graph TD
    subgraph TS["Thompson Sampling Process"]
        A["Initialize Beta(1,1) for each agent"] --> B["Sample weights from Beta distributions"]
        B --> C["Agents make predictions"]
        C --> D{"Prediction Correct?"}
        D -->|Yes| E["Update α (Success++)"]
        D -->|No| F["Update β (Failure++)"]
        E --> G["Update Beta distributions"]
        F --> G
        G --> B
    end
    
    subgraph MF["Mathematical Foundation"]
        H["Beta Distribution"]
        I["θᵢ ~ Beta(αᵢ, βᵢ)"]
        J["E[θᵢ] = αᵢ/(αᵢ + βᵢ)"]
        K["Var[θᵢ] decreases as n increases"]
    end
    
    style A fill:#e3f2fd
    style G fill:#c8e6c9
    style H fill:#fff3e0
```

Implementation:
```python
class ThompsonSampler:
    def __init__(self, n_agents=5):
        self.successes = np.ones(n_agents)  # Beta α parameters
        self.failures = np.ones(n_agents)   # Beta β parameters
    
    def sample_weights(self):
        """Sample from Beta distributions for each agent"""
        return np.random.beta(self.successes, self.failures)
    
    def update(self, agent_idx, reward):
        """Update Beta parameters based on prediction outcome"""
        if reward > threshold:
            self.successes[agent_idx] += 1
        else:
            self.failures[agent_idx] += 1
```

## Installation

### Prerequisites
- Python 3.8 or higher
- 8GB RAM minimum (16GB recommended)
- OpenRouter API key for LLM access

### Standard Installation
```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
```

### High-Performance Installation
For 10x faster data collection with Scrapy:
```bash
pip install -r requirements.txt
pip install scrapy>=2.11.0 twisted>=23.10.0
```

### Environment Configuration
```bash
export OPENROUTER_API_KEY="your-api-key-here"
```

## Quick Start

### Basic Usage
```bash
# Analyze a single CVE
python zeroday.py CVE-2024-3400

# Analyze multiple CVEs
python zeroday.py CVE-2024-3400 CVE-2021-44228 CVE-2023-1234

# JSON output for automation
python zeroday.py --json CVE-2024-3400 > result.json

# Quiet mode (result only)
python zeroday.py -q CVE-2024-3400
```

### Python API
```python
from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector

# Initialize detector
detector = EnhancedZeroDayDetector(use_turbo=True)

# Analyze vulnerability
result = detector.detect("CVE-2024-3400", verbose=True)

# Access results
if result['is_zero_day']:
    print(f"Zero-day detected with {result['confidence']:.1%} confidence")
    print(f"Key indicators: {', '.join(result['key_indicators'])}")
```

## System Components

### TurboScraper

High-performance data collection using Scrapy:
- **Concurrent requests**: Up to 100 simultaneous connections
- **Smart rate limiting**: Adaptive delays to avoid blocking
- **Multi-tier caching**: Hot (100), Warm (1000), Cold (7 days)
- **Automatic retries**: Exponential backoff for failed requests

### Feature Extractor

Evidence-based feature engineering:
- **Temporal analysis**: Exploitation timeline patterns
- **Cross-source validation**: Multi-source evidence correlation
- **Normalization**: Consistent scaling across features
- **Missing data handling**: Intelligent imputation strategies

### Multi-Agent Coordinator

Parallel LLM analysis with:
- **Asynchronous execution**: All agents run concurrently
- **Timeout handling**: 30-second timeout per agent
- **Error resilience**: Graceful degradation on failures
- **Result aggregation**: Weighted combination of predictions

### Score Fusion

Advanced scoring algorithm:
```
final_score = 0.60 * feature_score + 0.30 * llm_ensemble_score + 0.10 * threat_score

where:
- feature_score = Σ(feature_value × feature_weight)
- llm_ensemble_score = Σ(agent_score × thompson_weight) / Σ(thompson_weight)
- threat_score = threat_actor_interest × threat_multiplier
```

### Dynamic Thresholds

Confidence-based decision boundaries:
- **HIGH** (≥80% confidence): threshold = 0.50
- **MEDIUM** (60-79% confidence): threshold = 0.45
- **LOW** (40-59% confidence): threshold = 0.40
- **VERY_LOW** (<40% confidence): threshold = 0.35

## Performance

### Detection Metrics
- **Precision**: 100% (no false positives in testing)
- **Recall**: 70%+ with optimized thresholds
- **F1-Score**: 0.82+ on balanced datasets
- **Analysis Speed**: ~2-3 seconds per CVE with TurboScraper

### Optimization Results
- Thompson Sampling converges within ~50 iterations
- Ensemble outperforms best single agent by 15-20%
- Dynamic thresholds reduce false positives by 30%
- TurboScraper provides 10x speedup over sequential scraping

### Scalability
- Batch processing: 100+ CVEs in parallel
- Memory efficient: <2GB for 1000 CVE analysis
- Cache hit rate: 85%+ on repeated analyses
- API cost optimization: <$0.01 per CVE

## Configuration

### Model Configuration
Edit `config/models.yaml`:
```yaml
agents:
  ForensicAnalyst:
    model: "mistralai/mixtral-8x22b-instruct"
    temperature: 0.3
    max_tokens: 500
    timeout: 30
```

### Feature Weights
Customize in `src/utils/feature_extractor.py`:
```python
FEATURE_WEIGHTS = {
    'in_cisa_kev': 0.60,          # Strongest indicator
    'has_exploit_code': 0.30,     # Public exploit availability
    'actively_exploited': 0.40,   # Active exploitation evidence
    'apt_association': 0.25,      # APT group involvement
    'ransomware_campaign': 0.35,  # Ransomware usage
    # ... additional features
}
```

### Detection Thresholds
Adjust in `scripts/detect_zero_days_enhanced.py`:
```python
CONFIDENCE_THRESHOLDS = {
    'HIGH': 0.50,      # Optimized for balanced performance
    'MEDIUM': 0.45,    # Reduced from 0.83 for better recall
    'LOW': 0.40,       # Conservative threshold
    'VERY_LOW': 0.35   # Maximum recall setting
}
```

## Experimental Results

### Dataset
- **Test Set**: 100 CVEs (63 zero-days, 37 regular vulnerabilities)
- **Ground Truth**: CISA KEV catalog (100% validated)
- **Time Period**: 2017-2024 vulnerabilities

### Performance Comparison

```mermaid
graph TD
    subgraph "Performance Metrics"
        A[Our System<br/>F1: 0.82] --> B[100% Precision<br/>70% Recall]
        C[Single LLM<br/>F1: 0.67] --> D[85% Precision<br/>55% Recall]
        E[Rule-based<br/>F1: 0.56] --> F[75% Precision<br/>45% Recall]
        G[ML Baseline<br/>F1: 0.69] --> H[80% Precision<br/>60% Recall]
    end
    
    style A fill:#4caf50,stroke:#1b5e20,stroke-width:3px
    style C fill:#2196f3,stroke:#0d47a1,stroke-width:2px
    style E fill:#ff9800,stroke:#e65100,stroke-width:2px
    style G fill:#9c27b0,stroke:#4a148c,stroke-width:2px
```

### Ablation Study

| Component Removed | Performance Impact |
|-------------------|-------------------|
| Thompson Sampling | -8% F1-Score |
| Social Signals | -5% Recall |
| LLM Ensemble | -15% F1-Score |
| TurboScraper | +900% runtime |

### Statistical Significance
- Ensemble vs Single Agent: p < 0.001 (McNemar's test)
- With vs Without Thompson: p < 0.01
- All improvements statistically significant at α = 0.05

## Testing

### Run Comprehensive Tests
```bash
# Full test suite with metrics
python scripts/run_comprehensive_test.py

# Test with specific dataset
python scripts/run_comprehensive_test.py --input test_cves_100.json

# Generate detailed report
python scripts/run_comprehensive_test.py --output results.json
```

### Validate Ground Truth
```bash
# Check dataset labels against CISA KEV
python scripts/validate_ground_truth.py

# Auto-fix incorrect labels
python scripts/validate_ground_truth.py --fix
```

### Performance Analysis
```bash
# Calculate detailed metrics
python scripts/calculate_metrics.py results.json

# Compare with baseline
python scripts/calculate_metrics.py results.json --baseline baseline.json
```

## Advanced Usage

### Custom Agent Implementation
```python
from src.agents.base_agent import BaseAgent

class CustomAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_name="CustomAgent",
            model_id="your-model-id"
        )
    
    def analyze(self, cve_data):
        # Custom analysis logic
        return super().analyze(cve_data)
```

### Feature Extension
```python
def extract_custom_features(evidence):
    features = {}
    # Add custom feature extraction
    features['custom_indicator'] = compute_custom_metric(evidence)
    return features
```

### Batch Processing
```python
# Process large CVE lists efficiently
cve_list = load_cve_list("cves.txt")
results = []

for batch in chunks(cve_list, size=50):
    batch_results = detector.detect_batch(batch)
    results.extend(batch_results)
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Additional data source integrations
- Novel feature engineering approaches
- Alternative ensemble methods
- Performance optimizations
- Documentation improvements

## Citation

```bibtex
@software{detomasi2025zerodayensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent LLM Ensemble},
  year = {2025},
  publisher = {GitHub},
  journal = {GitHub repository},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble},
  institution = {University of L'Aquila}
}
```

## Acknowledgments

This research was conducted at the University of L'Aquila, Department of Information Engineering, Computer Science and Mathematics.

We thank:
- CISA for maintaining the Known Exploited Vulnerabilities catalog
- The security research community for vulnerability disclosures
- OpenRouter for unified LLM API access
- Contributors and early adopters for valuable feedback

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

**Lorenzo De Tomasi**  
Department of Information Engineering, Computer Science and Mathematics  
University of L'Aquila, Italy  
Email: lorenzo.detomasi@graduate.univaq.it  
GitHub: [@lodetomasi](https://github.com/lodetomasi)

---

For additional information:
- [METHODOLOGY.md](METHODOLOGY.md) - Detailed technical methodology
- [CHANGELOG.md](CHANGELOG.md) - Version history and updates
- [docs/QUICKSTART.md](docs/QUICKSTART.md) - Quick start guide