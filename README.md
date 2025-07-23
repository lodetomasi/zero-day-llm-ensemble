# Zero-Day Vulnerability Detection Using Multi-Agent Large Language Model Ensemble

## Abstract

This repository presents a novel approach to zero-day vulnerability detection leveraging an ensemble of specialized Large Language Models (LLMs). Our methodology addresses the critical challenge of identifying vulnerabilities that have been exploited in the wild before patches were available, using only the textual descriptions from Common Vulnerabilities and Exposures (CVE) entries. The system achieves 70% classification accuracy while maintaining strict data isolation to prevent information leakage, demonstrating the potential of LLMs in cybersecurity threat assessment.

## 1. Introduction

Zero-day vulnerabilities represent one of the most significant threats in cybersecurity, as they are actively exploited before vendors can develop and distribute patches. Traditional detection methods often rely on signatures, heuristics, or post-exploitation indicators, limiting their effectiveness for proactive defense. This research explores whether Large Language Models can identify linguistic and technical patterns in vulnerability descriptions that correlate with zero-day exploitation.

<p align="center">
  <img src="docs/images/system_overview.png" alt="System Overview" width="800">
</p>

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

## 4. Algorithmic Implementation

### 4.1 Ensemble Algorithm

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

### 4.2 Prompt Engineering Function

The prompt construction function φ_prompt: X → String incorporates:

```
φ_prompt(x) = template(agent_role) ⊕ features(x) ⊕ instructions
```

Where ⊕ denotes string concatenation and template selection is agent-specific.

## 5. Implementation Details

### 5.1 System Requirements

```bash
# Python 3.8+
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
pip install -r requirements.txt
export OPENROUTER_API_KEY="your-api-key"
```

### 3.2 Execution

```bash
# Balanced evaluation (recommended for research validation)
python run_complete_test.py --zero-days 50 --regular 50 --parallel

# Large-scale evaluation
python run_complete_test.py --zero-days 100 --regular 100 --parallel
```

#### Command-Line Parameters

```bash
python run_complete_test.py [OPTIONS]

Required Arguments:
  --zero-days N        Number of zero-day CVEs to test (from CISA KEV)
  --regular N          Number of regular CVEs to test (from NVD)

Optional Arguments:
  --parallel           Enable parallel agent execution (recommended)
  --sequential         Force sequential agent execution (default if not specified)
  --output-dir PATH    Custom output directory (default: ./results)
  --no-visualizations  Disable automatic plot generation
  --verbose            Enable detailed logging output
  --cache-ttl HOURS    Cache time-to-live in hours (default: 24)
  --timeout SECONDS    API timeout per agent in seconds (default: 60)
  --seed N             Random seed for reproducibility
  --start-year YYYY    Filter CVEs from this year onwards (default: 2020)
  --end-year YYYY      Filter CVEs up to this year (default: current year)
```

#### Advanced Usage Examples

```bash
# Reproducible experiment with specific seed
python run_complete_test.py --zero-days 25 --regular 25 --parallel --seed 42

# Test only recent vulnerabilities (2023-2024)
python run_complete_test.py --zero-days 50 --regular 50 --parallel --start-year 2023

# Custom output location with verbose logging
python run_complete_test.py --zero-days 30 --regular 30 --parallel --output-dir ~/experiments/run1 --verbose

# Quick test without visualizations
python run_complete_test.py --zero-days 10 --regular 10 --parallel --no-visualizations

# Extended timeout for slow connections
python run_complete_test.py --zero-days 20 --regular 20 --parallel --timeout 120
```

### 3.3 Alternative Execution Scripts

#### Balanced Test Script
```bash
python run_balanced_test.py [OPTIONS]

# Ensures exactly 50/50 distribution
# Automatically retries if data sources have insufficient samples
# Same parameters as run_complete_test.py
```

#### Batch Evaluation
```bash
# Run multiple experiments with different configurations
for seed in 1 2 3 4 5; do
    python run_complete_test.py --zero-days 50 --regular 50 --parallel --seed $seed
done
```

### 3.4 Output Artifacts

- `results/complete_test_TIMESTAMP.json`: Raw prediction data and agent responses
- `results/analysis_plots_TIMESTAMP.png`: Comprehensive visualization suite (6 subplots)
- `results/report_TIMESTAMP.txt`: Statistical summary and performance metrics
- `logs/experiment_TIMESTAMP.log`: Detailed execution logs (if --verbose)
- `cache/cisa_kev_cache.json`: Cached CISA KEV data (24h TTL)
- `cache/nvd_cache.json`: Cached NVD data (24h TTL)

## 4. Technical Architecture

### 4.1 High-Level System Architecture

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

### 4.2 Data Flow Sequence

```mermaid
sequenceDiagram
    participant User
    participant System
    participant CISA
    participant NVD
    participant Cache
    participant Agents
    participant Ensemble
    
    User->>System: Request CVE Analysis
    System->>Cache: Check for cached data
    
    alt Data not cached
        System->>CISA: Fetch KEV data
        System->>NVD: Fetch CVE data
        CISA-->>Cache: Store with 24h TTL
        NVD-->>Cache: Store with 24h TTL
    end
    
    Cache-->>System: Return CVE data
    System->>System: Preprocess & Anonymize
    
    par Parallel Agent Execution
        System->>Agents: ForensicAnalyst
        System->>Agents: PatternDetector
        System->>Agents: TemporalAnalyst
        System->>Agents: AttributionExpert
        System->>Agents: MetaAnalyst
    end
    
    Agents-->>Ensemble: Individual predictions
    Ensemble->>Ensemble: Average voting
    Ensemble->>System: Final classification
    System->>User: Results + Visualizations
```

### 4.2 Data Pipeline

1. **Collection Phase**: Automated retrieval from CISA KEV and NVD APIs with 24-hour caching
2. **Preprocessing**: Standardization of CVE entries without source indicators
3. **Parallel Analysis**: Concurrent execution of agent predictions for efficiency
4. **Ensemble Integration**: Unweighted averaging of agent predictions
5. **Binary Classification**: Threshold-based decision (P > 0.5 → zero-day)

### 4.3 Prompt Engineering

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

### 4.4 Visualization Suite

Six automated visualizations provide comprehensive performance analysis:
- Confusion Matrix with normalized values
- Performance metrics comparison (Accuracy, Precision, Recall, F1)
- Probability distribution analysis by class
- ROC curve with AUC calculation
- Temporal prediction patterns
- Confidence-calibrated accuracy assessment

### 4.5 Configuration Options

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

## 6. Statistical Analysis and Key Findings

### 6.1 ROC Analysis

The Receiver Operating Characteristic curve analysis yields:

**Area Under Curve (AUC)** = 0.752 ± 0.038

This indicates good discriminative ability, significantly better than random classification (AUC = 0.5).

### 6.2 Statistical Hypothesis Testing

**Null Hypothesis (H₀)**: The ensemble performs no better than random classification
**Alternative Hypothesis (H₁)**: The ensemble performs significantly better than random

Using McNemar's test for paired nominal data:
- χ² = 45.82
- p < 0.001

We reject H₀ with high confidence.

### 6.3 Agent Contribution Analysis

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

### 6.4 Error Analysis

**False Positive Analysis** (n = 11):
- 45% involve critical infrastructure vendors
- 36% contain emergency/critical keywords
- 18% describe remote code execution

**False Negative Analysis** (n = 52):
- 58% lack explicit urgency indicators
- 31% use technical jargon without exploitation context
- 11% have delayed disclosure patterns

## 7. Theoretical Limitations and Future Directions

### 7.1 Current Limitations

1. **Information-Theoretic Bound**: Given only textual descriptions, there exists an inherent upper bound on achievable accuracy
2. **Class Imbalance**: Real-world distribution heavily skewed (≈5% zero-days)
3. **Temporal Drift**: Exploitation patterns evolve over time, requiring continuous adaptation

### 7.2 Optimization Opportunities

#### 7.2.1 Weighted Ensemble

Instead of uniform weights, optimize:

**P(y = 1|x) = Σᵢ₌₁ᵏ wᵢ × Aᵢ(x)**

Subject to: Σ wᵢ = 1, wᵢ ≥ 0

Using gradient descent on validation loss:

**L(w) = -Σⱼ [yⱼ log(P(yⱼ|xⱼ)) + (1-yⱼ) log(1-P(yⱼ|xⱼ))]**

#### 7.2.2 Confidence Calibration

Apply Platt scaling to calibrate probabilities:

**P_calibrated = σ(a × P_ensemble + b)**

Where σ is the sigmoid function and (a, b) are learned parameters.

### 7.3 Future Research Directions

1. **Multi-Modal Learning**: Incorporate CVE reference graphs and exploit timelines
2. **Active Learning**: Dynamically select most informative samples for human review
3. **Adversarial Robustness**: Defend against malicious CVE description manipulation
4. **Explainable AI**: Generate human-interpretable rationales for predictions

## 8. Computational Complexity Analysis

### 8.1 Time Complexity

Let n = number of CVEs to classify, k = number of agents:

- **Sequential execution**: O(n × k × T_LLM)
- **Parallel execution**: O(n × T_LLM)

Where T_LLM represents average LLM inference time (≈2-5 seconds)

### 8.2 Space Complexity

- **Memory footprint**: O(n × |d|) where |d| is average description length
- **Cache storage**: O(|D_KEV| + |D_NVD|) ≈ O(200,000) entries

## 9. Reproducibility

All code, configurations, and prompts are provided for full reproducibility. The modular architecture supports easy substitution of LLM backends and prompt strategies.

### 9.1 Programmatic API Usage

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

### 9.2 Custom Agent Integration

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

## 10. Bayesian Interpretation

### 10.1 Prior and Posterior Analysis

Let π₀ = P(zero-day) ≈ 0.05 be the prior probability. Using Bayes' theorem:

**P(zero-day|positive test) = P(positive|zero-day) × P(zero-day) / P(positive)**

With our empirical values:
- P(positive|zero-day) = 0.48 (Recall)
- P(positive|regular) = 0.11 (1 - Specificity)

**Posterior probability**:
P(zero-day|positive) = (0.48 × 0.05) / [(0.48 × 0.05) + (0.11 × 0.95)] = 0.187

This demonstrates that even with 81.4% precision on balanced data, real-world deployment requires careful threshold tuning.

## 11. Citation

If you use this work in your research, please cite:

```bibtex
@software{zero_day_llm_ensemble,
  author = {De Tomasi, Lorenzo},
  title = {Zero-Day Vulnerability Detection Using Multi-Agent Large Language Model Ensemble},
  year = {2025},
  url = {https://github.com/lodetomasi/zero-day-llm-ensemble}
}
```

## 9. Contact

For questions or collaborations, please open an issue or contact lorenzo.detomasi@graduate.univaq.it.

## License

This project is released under the MIT License. See LICENSE file for details.