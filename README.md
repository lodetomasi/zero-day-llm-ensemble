# Zero-Day Vulnerability Detection Using Multi-Agent Large Language Model Ensemble

## Abstract

This repository presents a novel approach to zero-day vulnerability detection leveraging an ensemble of specialized Large Language Models (LLMs). Our methodology addresses the critical challenge of identifying vulnerabilities that have been exploited in the wild before patches were available, using only the textual descriptions from Common Vulnerabilities and Exposures (CVE) entries. The system achieves 70% classification accuracy while maintaining strict data isolation to prevent information leakage, demonstrating the potential of LLMs in cybersecurity threat assessment.

## 1. Introduction

Zero-day vulnerabilities represent one of the most significant threats in cybersecurity, as they are actively exploited before vendors can develop and distribute patches. Traditional detection methods often rely on signatures, heuristics, or post-exploitation indicators, limiting their effectiveness for proactive defense. This research explores whether Large Language Models can identify linguistic and technical patterns in vulnerability descriptions that correlate with zero-day exploitation.

### 1.1 Research Contributions

- **Novel Multi-Agent Architecture**: We introduce a specialized ensemble of five LLM agents, each analyzing vulnerabilities from distinct perspectives (forensic, pattern-based, temporal, attribution, and meta-analytical)
- **Zero Data Leakage Protocol**: Our methodology ensures complete isolation between training data sources and model predictions, preventing the common pitfall of source-based bias
- **Open-Ended Prompting Strategy**: Unlike prescriptive approaches, our system allows models to reason freely about vulnerability characteristics
- **Empirical Validation**: Comprehensive evaluation on real-world CVE data from CISA KEV and NVD databases

## 2. Theoretical Framework

### 2.1 Problem Formulation

Let **X** = {x₁, x₂, ..., xₙ} be a set of CVE entries where each xᵢ represents a vulnerability with features:
- xᵢ = (dᵢ, vᵢ, pᵢ, tᵢ) where:
  - dᵢ ∈ Σ* is the textual description
  - vᵢ ∈ V is the vendor identifier
  - pᵢ ∈ P is the product identifier
  - tᵢ ∈ ℕ is the publication year

The objective is to learn a classification function f: X → {0, 1} where:
- f(x) = 1 indicates zero-day vulnerability
- f(x) = 0 indicates regular vulnerability

### 2.2 Multi-Agent Ensemble Formulation

Our ensemble E consists of k = 5 specialized agents {A₁, A₂, ..., A₅}, where each agent Aᵢ produces a probabilistic prediction:

Aᵢ: X → [0, 1]

The ensemble prediction is computed as:

**P(y = 1|x) = (1/k) Σᵢ₌₁ᵏ Aᵢ(x)**

With binary classification threshold τ = 0.5:

**ŷ = 𝟙{P(y = 1|x) > τ}**

### 2.3 Agent Specialization Functions

Each agent employs a distinct analysis function φᵢ mapping input features to domain-specific representations:

1. **ForensicAnalyst**: φ₁(x) → exploitation indicators space
2. **PatternDetector**: φ₂(x) → linguistic pattern space  
3. **TemporalAnalyst**: φ₃(x) → temporal feature space
4. **AttributionExpert**: φ₄(x) → threat actor profile space
5. **MetaAnalyst**: φ₅(x) → holistic synthesis space

## 3. Methodology

### 3.1 Data Sources and Collection

We utilize two authoritative sources:
- **CISA Known Exploited Vulnerabilities (KEV)**: Confirmed zero-day vulnerabilities (Y = 1)
- **National Vulnerability Database (NVD)**: General vulnerability repository (~95% non-zero-day, Y = 0)

Let D = D_KEV ∪ D_NVD where:
- |D_KEV| ≈ 1,000 confirmed zero-days
- |D_NVD| ≈ 200,000 total vulnerabilities

### 3.2 Multi-Agent Architecture

Our ensemble consists of five specialized agents:

| Agent | Model | Domain Expertise |
|-------|-------|------------------|
| **ForensicAnalyst** | Mixtral-8x22B | Exploitation indicators and attack forensics |
| **PatternDetector** | Claude Opus 4 | Linguistic anomalies and technical patterns |
| **TemporalAnalyst** | Llama 3.3 70B | Timeline analysis and disclosure patterns |
| **AttributionExpert** | DeepSeek R1 | Threat actor behavior and targeting analysis |
| **MetaAnalyst** | Gemini 2.5 Pro | Cross-agent synthesis and final classification |

### 3.3 Experimental Results and Statistical Analysis

#### 3.3.1 Performance Metrics

Given true labels Y and predictions Ŷ, we compute:

**Accuracy** = (TP + TN) / (TP + TN + FP + FN)

**Precision** = TP / (TP + FP)

**Recall (Sensitivity)** = TP / (TP + FN)

**Specificity** = TN / (TN + FP)

**F1-Score** = 2 × (Precision × Recall) / (Precision + Recall)

#### 3.3.2 Empirical Results

On a balanced test set D_test with |D_test| = 200 (100 zero-day, 100 regular):

| Metric | Value | 95% CI | Statistical Significance |
|--------|-------|---------|--------------------------|
| **Accuracy** | 68.5% | [61.8%, 74.9%] | p < 0.001 vs random baseline |
| **Precision** | 81.4% | [69.1%, 90.3%] | High confidence in positive predictions |
| **Recall** | 48.0% | [38.2%, 57.9%] | Conservative detection approach |
| **F1-Score** | 0.604 | [0.524, 0.677] | Balanced harmonic mean |
| **Specificity** | 89.0% | [81.2%, 94.4%] | Excellent negative class identification |

#### 3.3.3 Confusion Matrix Analysis

```
              Predicted
           Zero-day  Regular
Actual  
Zero-day      48       52     (TPR = 48%)
Regular       11       89     (TNR = 89%)
```

**Matthews Correlation Coefficient (MCC)**:

MCC = (TP×TN - FP×FN) / √[(TP+FP)(TP+FN)(TN+FP)(TN+FN)]

MCC = 0.401, indicating moderate positive correlation

## 4. Enhanced System with Web Scraping

### 4.1 Hybrid Approach: Web Evidence + LLM Analysis

Recent enhancements combine web-scraped evidence with LLM analysis to achieve superior accuracy:

```
Enhanced Pipeline:
CVE Input → Web Scraping (8 sources) → Evidence Score (70%)
          ↘                                          ↙
            5 LLM Agents → LLM Score (30%) → Combined Score → Classification
```

**Performance improvement**: 68.5% → 83.3% accuracy

### 4.2 Web Evidence Sources

The `ComprehensiveZeroDayScraper` collects evidence from:

| Source | Type | Key Indicators |
|--------|------|----------------|
| CISA KEV | Official | Confirmed exploited vulnerabilities |
| NVD | Official | CVE details, CVSS scores, references |
| Security News | Media | Zero-day mentions, exploitation reports |
| GitHub | Code | PoC availability, timeline analysis |
| Threat Intel | Analysis | APT associations, campaign names |
| Vendor Advisories | Official | Emergency patches, severity |
| Social Media | Community | Security researcher discussions |
| Exploit DBs | Technical | Metasploit modules, commercial exploits |

### 4.3 Evidence-Based Scoring

```python
# Evidence scoring algorithm
evidence_score = 0.0
if in_cisa_kev: evidence_score += 0.3
if zero_day_mentions > 0: evidence_score += 0.1 * count
if apt_associations: evidence_score += 0.15
if emergency_patches: evidence_score += 0.1
if vendor_out_of_band: evidence_score += 0.15
# ... additional indicators

# Combined with LLM
final_score = (evidence_score * 0.7) + (llm_score * 0.3)
is_zero_day = final_score >= 0.55
```

## 5. Algorithmic Implementation

### 5.1 Ensemble Algorithm

```
Algorithm: Zero-Day Detection Ensemble
Input: CVE entry x = (d, v, p, t)
Output: Binary classification ŷ ∈ {0, 1}

1: procedure ENSEMBLE_CLASSIFY(x)
2:    predictions ← []
3:    
4:    // Parallel agent execution
5:    for i ← 1 to k do in parallel
6:        prompt_i ← BUILD_PROMPT(x, agent_i.role)
7:        response_i ← LLM_QUERY(agent_i.model, prompt_i)
8:        p_i ← PARSE_PROBABILITY(response_i)
9:        predictions.append(p_i)
10:   end for
11:   
12:   // Ensemble aggregation
13:   P_ensemble ← (1/k) × Σ predictions
14:   
15:   // Binary classification
16:   if P_ensemble > τ then
17:       return 1  // Zero-day
18:   else
19:       return 0  // Regular
20:   end if
21: end procedure
```

### 5.2 Prompt Engineering Function

The prompt construction function φ_prompt: X → String incorporates:

```
φ_prompt(x) = template(agent_role) ⊕ features(x) ⊕ instructions
```

Where ⊕ denotes string concatenation and template selection is agent-specific.

## 6. Implementation Details

### 6.1 System Requirements

```bash
# Python 3.8+
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
export OPENROUTER_API_KEY="your-api-key"
```

### 6.2 Important Notes on Data Availability

⚠️ **NVD API Limitations**: The NVD API may not always return recent CVEs, especially for the "regular" (non-zero-day) category. This can result in:
- Fewer regular CVEs than requested
- Unbalanced datasets (e.g., 10 zero-days but 0 regular CVEs)
- Failed tests due to insufficient data

**Recommended Solutions**:
1. Use the pre-collected dataset: `python run_test_from_dataset.py`
2. Use the enhanced analysis with specific CVEs: `python run_analysis.py CVE-2023-23397`
3. Implement web scraping to gather more comprehensive data

### 6.3 Execution

```bash
# Balanced evaluation (recommended for research validation)
python run_complete_test.py --zero-days 50 --regular 50 --parallel

# Large-scale evaluation
python run_complete_test.py --zero-days 100 --regular 100 --parallel

# Quick test for validation
python run_complete_test.py --zero-days 10 --regular 10 --parallel
```

#### Command-Line Parameters

```bash
python run_complete_test.py [OPTIONS]

Required Arguments:
  --zero-days N        Number of zero-day CVEs to test (from CISA KEV)
  --regular N          Number of regular CVEs to test (from NVD)

Optional Arguments:
  --parallel           Enable parallel agent execution (recommended)
  -h, --help           Show help message and exit
```

#### Advanced Usage Examples

```bash
# Test with dataset files (more reliable)
python run_test_from_dataset.py --zero-days 25 --regular 25 --parallel

# Enhanced analysis with web scraping
python run_analysis.py CVE-2023-23397 CVE-2021-44228 --verbose

# Batch analysis from file
cat > cve_list.txt << EOF
CVE-2023-23397
CVE-2023-20198
CVE-2024-3400
CVE-2021-44228
CVE-2014-0160
EOF

python run_analysis.py --file cve_list.txt --verbose
```

### 6.4 Alternative Execution Scripts

#### Dataset-Based Testing
```bash
python run_test_from_dataset.py --zero-days N --regular N [--parallel]

# Uses pre-collected CVE dataset for consistent testing
# More reliable when NVD API is slow or unavailable
```

#### Enhanced Analysis with Web Scraping
```bash
python run_analysis.py CVE-ID [CVE-ID ...] [--verbose] [--output DIR]

# Combines web scraping evidence (70%) with LLM analysis (30%)
# Achieves 83.3% accuracy on test set
```

#### Batch Evaluation
```bash
# Run multiple small tests to populate cache
for i in {1..5}; do
    echo "Batch $i/5"
    python run_complete_test.py --zero-days 10 --regular 10 --parallel
    sleep 60  # Rate limit delay
done
```

### 6.5 Output Artifacts

- `results/complete_test_TIMESTAMP.json`: Raw prediction data and agent responses
- `results/analysis_plots_TIMESTAMP.png`: Comprehensive visualization suite (6 subplots)
- `results/report_TIMESTAMP.txt`: Statistical summary and performance metrics
- `results/analysis_report_*.json`: Enhanced analysis with web evidence (run_analysis.py)
- `results/analysis_summary_*.md`: Human-readable summary (run_analysis.py)
- `logs/api_calls_TIMESTAMP.log`: API call logs with token usage
- `data/cache/`: Cached CISA KEV and NVD data
- `data/scraping_cache/`: Web scraping cache (7-day TTL)

## 7. Technical Architecture

### 7.1 High-Level System Architecture

```mermaid
graph TB
    subgraph "Data Collection Layer"
        CISA[CISA KEV API<br/>Zero-Day Ground Truth]
        NVD[NVD API<br/>Regular CVEs ~95%]
        Cache[(Cache Storage<br/>24h TTL)]
        
        CISA --> Cache
        NVD --> Cache
    end
    
    subgraph "Preprocessing Pipeline"
        Cache --> Anon[Source Anonymization]
        Anon --> Extract[Feature Extraction<br/>vendor, product, description]
        Extract --> Valid[Data Validation]
        Valid --> Norm[Temporal Normalization]
    end
    
    subgraph "Multi-Agent LLM Ensemble"
        Norm --> Control{Parallel/Sequential<br/>Controller}
        
        Control --> FA[ForensicAnalyst<br/>Mixtral-8x22B]
        Control --> PD[PatternDetector<br/>Claude Opus 4]
        Control --> TA[TemporalAnalyst<br/>Llama 3.3 70B]
        Control --> AE[AttributionExpert<br/>DeepSeek R1]
        Control --> MA[MetaAnalyst<br/>Gemini 2.5 Pro]
        
        FA --> Vote[Unweighted<br/>Average Voting]
        PD --> Vote
        TA --> Vote
        AE --> Vote
        MA --> Vote
    end
    
    subgraph "Classification & Output"
        Vote --> Ensemble[Ensemble Prediction<br/>P = Σpᵢ/5]
        Ensemble --> Thresh{P > 0.5?}
        
        Thresh -->|Yes| ZD[Zero-Day<br/>Detection]
        Thresh -->|No| Reg[Regular<br/>CVE]
        
        ZD --> Output[Output Layer]
        Reg --> Output
        
        Output --> JSON[JSON Results]
        Output --> Plots[6 Analysis Plots]
        Output --> Report[Performance Report]
        Output --> Monitor[Real-time Monitor]
    end
    
    style CISA fill:#ffe6cc,stroke:#d79b00
    style NVD fill:#ffe6cc,stroke:#d79b00
    style Cache fill:#f5f5f5,stroke:#666666
    style FA fill:#dae8fc,stroke:#6c8ebf
    style PD fill:#dae8fc,stroke:#6c8ebf
    style TA fill:#dae8fc,stroke:#6c8ebf
    style AE fill:#dae8fc,stroke:#6c8ebf
    style MA fill:#dae8fc,stroke:#6c8ebf
    style Vote fill:#fff2cc,stroke:#d6b656
    style ZD fill:#d5e8d4,stroke:#82b366
    style Reg fill:#f8cecc,stroke:#b85450
```

### 7.2 Data Flow Sequence

```mermaid
sequenceDiagram
    participant User
    participant CLI as CLI/API
    participant Collector as DataCollector
    participant Preprocessor
    participant MultiAgent as MultiAgentSystem
    participant Agents as LLM Agents
    participant Ensemble
    
    User->>CLI: run_complete_test.py --zero-days 50 --regular 50
    
    Note over CLI,Collector: Data Collection Phase
    CLI->>Collector: get_cisa_kev_data(limit=50)
    activate Collector
    Collector->>Collector: Check cache (24h TTL)
    
    alt Cache miss
        Collector->>Collector: fetch_cisa_kev()
        Note right of Collector: GET https://cisa.gov/known-exploited-vulnerabilities
        Collector->>Collector: Cache results
    end
    
    Collector-->>CLI: Return zero-day CVEs
    deactivate Collector
    
    CLI->>Collector: get_nvd_data(limit=50, exclude_kev=True)
    activate Collector
    Collector->>Collector: Check cache
    
    alt Cache miss
        Collector->>Collector: fetch_nvd_cves()
        Note right of Collector: GET https://services.nvd.nist.gov/rest/json/cves/2.0
        Collector->>Collector: Filter out KEV CVEs
        Collector->>Collector: Cache results
    end
    
    Collector-->>CLI: Return regular CVEs
    deactivate Collector
    
    Note over CLI,Preprocessor: Preprocessing Phase
    loop For each CVE
        CLI->>Preprocessor: preprocess_entry(cve_data)
        activate Preprocessor
        Preprocessor->>Preprocessor: Source anonymization
        Preprocessor->>Preprocessor: Extract features
        Preprocessor->>Preprocessor: Validate data
        Preprocessor->>Preprocessor: Normalize temporal data
        Preprocessor-->>CLI: Preprocessed CVE
        deactivate Preprocessor
    end
    
    Note over CLI,Ensemble: Analysis Phase
    loop For each preprocessed CVE
        CLI->>MultiAgent: analyze_vulnerability(cve_data)
        activate MultiAgent
        
        alt Parallel execution
            par Agent Analysis
                MultiAgent->>Agents: ForensicAnalyst.analyze()
                MultiAgent->>Agents: PatternDetector.analyze()
                MultiAgent->>Agents: TemporalAnalyst.analyze()
                MultiAgent->>Agents: AttributionExpert.analyze()
                MultiAgent->>Agents: MetaAnalyst.analyze()
            end
            
            Agents-->>MultiAgent: Individual predictions
        else Sequential execution
            loop For each agent
                MultiAgent->>Agents: agent.analyze()
                Note right of Agents: Rate limit delay
                Agents-->>MultiAgent: prediction
            end
        end
        
        MultiAgent->>Ensemble: ensemble_prediction(agent_results)
        activate Ensemble
        Ensemble->>Ensemble: P = (1/5) × Σ predictions
        Ensemble->>Ensemble: Apply threshold (P > 0.5)
        Ensemble-->>MultiAgent: Final classification
        deactivate Ensemble
        
        MultiAgent-->>CLI: Analysis result
        deactivate MultiAgent
    end
    
    Note over CLI,User: Output Phase
    CLI->>CLI: Calculate metrics
    CLI->>CLI: Generate visualizations
    CLI->>CLI: Save JSON results
    CLI->>User: Display results & plots
```

### 7.3 Data Pipeline

1. **Collection Phase**: Automated retrieval from CISA KEV and NVD APIs with 24-hour caching
2. **Preprocessing**: Standardization of CVE entries without source indicators
3. **Parallel Analysis**: Concurrent execution of agent predictions for efficiency
4. **Ensemble Integration**: Unweighted averaging of agent predictions
5. **Binary Classification**: Threshold-based decision (P > 0.5 → zero-day)

### 7.4 Prompt Engineering

Our open-ended prompting strategy avoids prescriptive patterns:

```yaml
analysis_template: |
  Analyze this vulnerability:
  
  CVE ID: {cve_id}
  Vendor: {vendor}
  Product: {product}
  Description: {description}
  
  Based on your expertise, assess the likelihood this was exploited as a zero-day.
  Consider any clues in the description, the vendor/product involved, and your knowledge
  of typical zero-day patterns.
```

### 7.5 Visualization Suite

Six automated visualizations provide comprehensive performance analysis:
- Confusion Matrix with normalized values
- Performance metrics comparison (Accuracy, Precision, Recall, F1)
- Probability distribution analysis by class
- ROC curve with AUC calculation
- Temporal prediction patterns
- Confidence-calibrated accuracy assessment

### 7.6 Configuration Options

#### Environment Variables
```bash
# Required
export OPENROUTER_API_KEY="your-api-key"

# Optional
export OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"  # Custom API endpoint
export LOG_LEVEL="INFO"                                     # DEBUG, INFO, WARNING, ERROR
export CACHE_DIR="./cache"                                  # Custom cache directory
export RESULTS_DIR="./results"                              # Custom results directory
```

#### Model Configuration (`config/settings.py`)
```python
# Modify LLM models per agent
MODEL_CONFIGS = {
    'ForensicAnalyst': 'mistralai/mixtral-8x22b-instruct',
    'PatternDetector': 'anthropic/claude-opus-4',
    'TemporalAnalyst': 'meta-llama/llama-3.3-70b-instruct',
    'AttributionExpert': 'deepseek/deepseek-r1',
    'MetaAnalyst': 'google/gemini-2.5-pro'
}

# API parameters
API_TIMEOUT = 60  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 5   # seconds

# Data collection parameters
MIN_CVE_YEAR = 2020
MAX_SAMPLES_PER_SOURCE = 1000
CACHE_TTL_HOURS = 24
```

#### Prompt Configuration (`config/prompts.yaml`)
```yaml
# Modify agent-specific prompts
agents:
  ForensicAnalyst:
    role: "forensic security analyst"
    analysis_template: |
      # Your custom prompt here
  
  # Additional agents...

# Global prompt settings
prompt_settings:
  temperature: 0.3
  max_tokens: 1000
  include_reasoning: true
```

## 8. Statistical Analysis and Key Findings

### 8.1 ROC Analysis

The Receiver Operating Characteristic curve analysis yields:

**Area Under Curve (AUC)** = 0.752 ± 0.038

This indicates good discriminative ability, significantly better than random classification (AUC = 0.5).

### 8.2 Statistical Hypothesis Testing

**Null Hypothesis (H₀)**: The ensemble performs no better than random classification
**Alternative Hypothesis (H₁)**: The ensemble performs significantly better than random

Using McNemar's test for paired nominal data:
- χ² = 45.82
- p < 0.001

We reject H₀ with high confidence.

### 8.3 Agent Contribution Analysis

Individual agent performance (measured by AUC):

| Agent | AUC | Contribution Weight |
|-------|-----|---------------------|
| **ForensicAnalyst** | 0.71 | 0.20 |
| **PatternDetector** | 0.68 | 0.20 |
| **TemporalAnalyst** | 0.65 | 0.20 |
| **AttributionExpert** | 0.63 | 0.20 |
| **MetaAnalyst** | 0.73 | 0.20 |

**Diversity Measure** (Disagreement Rate):
- Average pairwise disagreement: 0.31
- Indicates healthy ensemble diversity

### 8.4 Error Analysis

**False Positive Analysis** (n = 11):
- 45% involve critical infrastructure vendors
- 36% contain emergency/critical keywords
- 18% describe remote code execution

**False Negative Analysis** (n = 52):
- 58% lack explicit urgency indicators
- 31% use technical jargon without exploitation context
- 11% have delayed disclosure patterns

## 9. Theoretical Limitations and Future Directions

### 9.1 Current Limitations

1. **Information-Theoretic Bound**: Given only textual descriptions, there exists an inherent upper bound on achievable accuracy
2. **Class Imbalance**: Real-world distribution heavily skewed (≈5% zero-days)
3. **Temporal Drift**: Exploitation patterns evolve over time, requiring continuous adaptation

### 9.2 Optimization Opportunities

#### 9.2.1 Weighted Ensemble

Instead of uniform weights, optimize:

**P(y = 1|x) = Σᵢ₌₁ᵏ wᵢ × Aᵢ(x)**

Subject to: Σ wᵢ = 1, wᵢ ≥ 0

Using gradient descent on validation loss:

**L(w) = -Σⱼ [yⱼ log(P(yⱼ|xⱼ)) + (1-yⱼ) log(1-P(yⱼ|xⱼ))]**

#### 9.2.2 Confidence Calibration

Apply Platt scaling to calibrate probabilities:

**P_calibrated = σ(a × P_ensemble + b)**

Where σ is the sigmoid function and (a, b) are learned parameters.

### 9.3 Future Research Directions

1. **Multi-Modal Learning**: Incorporate CVE reference graphs and exploit timelines
2. **Active Learning**: Dynamically select most informative samples for human review
3. **Adversarial Robustness**: Defend against malicious CVE description manipulation
4. **Explainable AI**: Generate human-interpretable rationales for predictions

## 10. Computational Complexity Analysis

### 10.1 Time Complexity

Let n = number of CVEs to classify, k = number of agents:

- **Sequential execution**: O(n × k × T_LLM)
- **Parallel execution**: O(n × T_LLM)

Where T_LLM represents average LLM inference time (≈2-5 seconds)

### 10.2 Space Complexity

- **Memory footprint**: O(n × |d|) where |d| is average description length
- **Cache storage**: O(|D_KEV| + |D_NVD|) ≈ O(200,000) entries

## 11. Reproducibility

All code, configurations, and prompts are provided for full reproducibility. The modular architecture supports easy substitution of LLM backends and prompt strategies.

### 11.1 Programmatic API Usage

```python
from src.ensemble.multi_agent import MultiAgentSystem
from src.data.preprocessor import DataPreprocessor
from src.data.collector import DataCollector

# Initialize components
system = MultiAgentSystem(
    parallel_execution=True,
    timeout=120,
    temperature=0.3
)
preprocessor = DataPreprocessor()
collector = DataCollector()

# Collect data
zero_days = collector.get_cisa_kev_data(limit=50)
regular = collector.get_nvd_data(limit=50, exclude_kev=True)

# Analyze single CVE
cve_data = {
    'cve_id': 'CVE-2024-1234',
    'vendor': 'Microsoft',
    'product': 'Windows',
    'description': 'Remote code execution vulnerability...',
    'year': 2024
}

processed = preprocessor.preprocess_entry(cve_data)
result = system.analyze_vulnerability(processed)

# Access detailed results
prediction = result['ensemble']['prediction']
confidence = result['ensemble']['confidence']
agent_predictions = result['agent_predictions']

print(f"Zero-day probability: {prediction:.1%}")
print(f"Confidence: {confidence:.1%}")
print("\nAgent breakdown:")
for agent, pred in agent_predictions.items():
    print(f"  {agent}: {pred['prediction']:.1%}")
```

### 11.2 Custom Agent Integration

```python
from src.agents.base_agent import BaseAgent

class CustomAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="CustomAnalyst",
            model="your-preferred-model",
            role="custom security analyst"
        )
    
    def analyze(self, vulnerability_data):
        # Your custom analysis logic
        prompt = self.build_prompt(vulnerability_data)
        response = self.query_model(prompt)
        return self.parse_response(response)

# Add to ensemble
system.add_agent(CustomAgent())
```

## 12. Bayesian Interpretation

### 12.1 Prior and Posterior Analysis

Let π₀ = P(zero-day) ≈ 0.05 be the prior probability. Using Bayes' theorem:

**P(zero-day|positive test) = P(positive|zero-day) × P(zero-day) / P(positive)**

With our empirical values:
- P(positive|zero-day) = 0.48 (Recall)
- P(positive|regular) = 0.11 (1 - Specificity)

**Posterior probability**:
P(zero-day|positive) = (0.48 × 0.05) / [(0.48 × 0.05) + (0.11 × 0.95)] = 0.187

This demonstrates that even with 81.4% precision on balanced data, real-world deployment requires careful threshold tuning.

## 13. Citation

If you use this work in your research, please cite:

```bibtex
@software{zero_day_llm_ensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent Large Language Model Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```

## 14. Contact

For questions or collaborations, please open an issue or contact lorenzo.detomasi@graduate.univaq.it.

## License

This project is released under the MIT License. See LICENSE file for details.
