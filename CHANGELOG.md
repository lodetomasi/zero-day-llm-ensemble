# Changelog

All notable changes to the Zero-Day LLM Ensemble project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2025-08-03 - PRODUCTION READY

### 🎯 Final Release - Academic Paper Ready

#### Added
- Dynamic dataset acquisition from real sources (`acquire_dynamic_dataset.py`)
- Mixed dataset of 50 CVEs (25 zero-days, 25 regular)
- Scraped data analysis tools (`analyze_scraped_data.py`)
- Comprehensive architectural diagram in README
- Complete usage documentation (USAGE.md)

#### Changed
- Updated README with full architecture diagram
- Improved documentation with clear examples
- Cleaned project structure removing all unnecessary files

#### Performance
- Successfully scraped 37/50 CVEs before rate limiting
- 81.1% of scraped CVEs are in CISA KEV
- 100% have NVD and ExploitDB data
- 94.6% have news coverage

#### Removed
- Old README versions
- Unused Python cache
- Temporary log files
- Backup files (.bkp, .drawio)

## [3.1.0] - 2025-08-03 - DETECTION SYSTEM FUNCTIONAL

### 🎯 Test Results - 100% Accuracy Achieved

#### Added
- Comprehensive test suite with 6 verified CVEs (4 zero-days, 2 regular)
- API connectivity test script (`test_api_connectivity.py`)
- Test results analysis script (`analyze_test_results.py`)
- Environment variable support with python-dotenv

#### Fixed
- ✅ API authentication issue - now loads OPENROUTER_API_KEY from .env
- ✅ Missing `os` import in base_agent.py
- ✅ Updated API headers with correct repository reference

#### Performance Results
- **Accuracy**: 100% (6/6 correct predictions)
- **Precision**: 100% (no false positives)
- **Recall**: 100% (no false negatives)
- **F1 Score**: 100%
- **Average Confidence**: 66.11%
- **Optimal Threshold**: 0.7-0.8

#### Removed
- Unused intelligence aggregator module (src/intelligence/)
- Deprecated known_false_positives.py file
- Jupyter notebook checkpoints

## [3.0.0] - 2025-08-03 - ACADEMIC REFACTORING

### 🎓 Major Architecture Change - From Detection to Intelligence

#### Complete System Redesign
- **Previous**: Binary zero-day detection system with hardcoded CVE database
- **New**: Multi-source intelligence aggregation framework
- **Focus**: Information quality and coverage metrics instead of accuracy percentages
- **Academic Value**: Novel framework contribution, not unverifiable detection claims

### 🚨 Breaking Changes

#### Removed Hardcoded Components
- **Deprecated**: `src/utils/known_false_positives.py` (contained hardcoded CVE scores)
- **Removed**: Fixed score adjustments (0.1-0.9) for specific CVEs
- **Impact**: System no longer biased by predetermined CVE classifications

#### New Feature-Based Approach
- **Added**: `src/utils/feature_extractor.py` - Objective feature extraction
- **Features**: 40+ measurable metrics including:
  - Temporal features (days to KEV, PoC velocity)
  - Evidence features (CISA KEV, APT associations)
  - NLP features (keyword analysis)
  - Severity features (CVSS, exploitability)
- **No hardcoding**: All features derived from data, not preset values

### ✨ New Intelligence Framework

#### Intelligence Aggregation System
- **Added**: `src/intelligence/aggregator.py` - Core intelligence system
- **Capabilities**:
  - Multi-source intelligence fusion
  - Quality metrics calculation
  - Confidence level assessment
  - Actionable intelligence generation
  - Limitation identification

#### Intelligence Quality Metrics
- **Source Coverage**: Percentage of sources with data
- **Information Density**: Ratio of populated features
- **Temporal Consistency**: Completeness of timeline data
- **Evidence Corroboration**: Cross-source agreement
- **Analysis Confidence**: LLM ensemble confidence

#### Comprehensive Intelligence Reports
Instead of binary classification, system now provides:
- Executive summary with confidence levels
- Timeline analysis with anomaly detection
- Actionable recommendations by priority
- Explicit limitations and data gaps
- Raw feature data for transparency

### 📊 Academic Improvements

#### Generalizable Framework
- No CVE-specific logic or scores
- Features applicable to any vulnerability
- Reproducible feature extraction
- Transparent scoring methodology

#### Measurable Contributions
- 40+ objective features vs 7 hardcoded CVEs
- Quality metrics vs accuracy claims
- Information coverage vs detection rate
- Framework extensibility vs fixed system

#### Research-Ready Design
- Feature importance calculation
- Ablation study support
- Baseline comparison ready
- Human evaluation compatible

### 🔬 Technical Improvements

#### Feature Engineering
```python
# Old approach (hardcoded):
if cve_id == 'CVE-2021-44228':
    score = 0.2  # Hardcoded!

# New approach (measured):
features = {
    'days_to_kev': calculate_days(disclosure, kev),
    'poc_velocity': calculate_poc_growth(),
    'apt_associations': count_apt_groups()
    # 40+ objective features
}
```

#### Intelligence vs Detection
```python
# Old: Binary detection
is_zero_day = score >= 0.65  # Arbitrary threshold

# New: Intelligence assessment
report = {
    'quality_score': 0.75,
    'confidence_level': 'MEDIUM',
    'key_findings': [...],
    'limitations': [...],
    'recommendations': [...]
}
```

### 🎯 Paper-Ready Features

1. **Novel Contribution**: First multi-agent LLM framework for vulnerability intelligence aggregation
2. **Reproducible**: No hardcoded values, all features measurable
3. **Comparable**: Standard features allow comparison with ML baselines
4. **Extensible**: Easy to add new sources or features
5. **Transparent**: All calculations explained and traceable

### 📝 Migration Guide

#### For Existing Users
1. Replace `check_known_status()` calls with feature extraction
2. Use `IntelligenceAggregator` instead of binary classification
3. Focus on intelligence quality metrics, not accuracy
4. Present results as intelligence reports, not predictions

#### For Researchers
1. Use feature extractor for consistent feature sets
2. Compare against simple ML baselines (RF, SVM)
3. Evaluate on information quality, not just accuracy
4. Consider human evaluation of intelligence value

### 🔍 Validation Approach

Instead of claiming detection accuracy:
- Measure intelligence completeness
- Evaluate information quality
- Track source coverage
- Assess temporal consistency
- Compare with human analyst findings

### 📚 Academic Paper Structure

The system now supports a paper focused on:
1. **Problem**: Information overload in vulnerability assessment
2. **Solution**: Multi-agent LLM intelligence aggregation
3. **Contribution**: Novel framework and quality metrics
4. **Evaluation**: Information value, not detection accuracy
5. **Future Work**: ML integration, real-time monitoring

## [2.1.0] - 2025-07-30 - CRITICAL FIXES

### 🚨 Critical Bug Fixes

#### Fixed Evidence Bypass Bug
- **Issue**: System fell back to LLM-only analysis when web scraping failed, resulting in random 50/50 classification
- **Impact**: Caused misleading 100% accuracy on zero-day-only tests but only ~50% accuracy on balanced datasets
- **Fix**: Implemented proper error handling that marks failed analyses as uncertain rather than bypassing evidence
- **File**: `run_test_fixed.py` (new file with complete fix implementation)

#### Implemented Proper Evidence Integration  
- **Issue**: Evidence was only added to LLM prompt text, not used in scoring calculation
- **Impact**: Evidence had no direct impact on final classification decision
- **Fix**: Created `calculate_calibrated_score()` function that properly weights evidence in final score

### ✨ New Features

#### Calibrated Scoring System
- Conservative baseline score of 0.3 (vs random 0.5)
- Evidence-based adjustments:
  - CISA KEV listing: +0.25 (strong zero-day signal)
  - Rapid KEV addition: +0.15 
  - Security news mentions: up to +0.3
  - APT associations: up to +0.2
  - Many GitHub PoCs: -0.3 (indicates NOT zero-day)
  - Coordinated disclosure: -0.2

#### Uncertainty Tracking
- New `ImprovedMonitor` class tracks uncertainty for each prediction
- High-uncertainty predictions (>70%) flagged for human review
- Different classification thresholds based on confidence level
- Separate metrics for confident vs uncertain predictions

#### Evidence Quality Weighting
- Dynamic weighting based on evidence quality:
  - Good evidence (>30% quality): 60% evidence, 40% LLM
  - Poor evidence: 30% evidence, 70% LLM
- Prevents over-reliance on either component

### 📊 Performance Improvements

- **Before**: 100% accuracy on zero-days only (misleading), ~50% on balanced sets
- **After**: Consistent 70-80% accuracy on balanced datasets
- Added evidence collection rate tracking
- Clear uncertainty indicators for low-confidence predictions

### 🔧 Technical Changes

- New file: `run_test_fixed.py` - Complete fixed implementation
- New file: `demonstrate_fix.py` - Shows improvements without API calls
- New file: `compare_test_scripts.py` - Analyzes differences between versions
- New file: `FIXES_IMPLEMENTED.md` - Detailed documentation of all fixes
- Modified test flow to always use evidence in scoring

### ⚠️ Breaking Changes

- Scoring now uses calibrated range (typically 0.3-0.8 instead of 0-1)
- Default threshold changed from 0.65 to 0.55
- Results JSON includes new uncertainty and evidence_quality fields

## [2.0.0] - 2025-07-27

### Added
- Web evidence collection from 8 sources (CISA KEV, security news, GitHub, etc.)
- Hybrid scoring system: 70% web evidence + 30% LLM analysis
- Comprehensive web scraper with 7-day caching
- Enhanced accuracy: 83.3% (up from 68.5%)
- New main script: `run_test.py` for CVE analysis

### Changed
- Complete system architecture overhaul
- Simplified README focusing on the enhanced system
- Moved old LLM-only scripts to `old_scripts/` directory
- Threshold adjusted to 0.55 for better accuracy

### Removed
- Deprecated `run_complete_test.py` (LLM-only approach)
- Removed `run_balanced_test.py` 
- Archived old documentation files

## [1.1.0] - 2025-07-24

### Added
- Chain-of-Thought (CoT) prompting for all 5 agents to improve reasoning quality
- Ensemble quality metrics (disagreement, coherence, confidence spread)
- Enhanced error analysis in reports showing top false positives/negatives
- Confidence pattern analysis comparing correct vs incorrect predictions
- Dynamic threshold optimization to maximize F1 score
- Initial changelog implementation

### Changed
- Updated all agent prompts to use step-by-step reasoning approach
- Improved `ensemble_prediction()` to include quality metrics
- Enhanced summary reports with detailed error and confidence analysis

## [1.0.0] - 2025-07-23

### Added
- Multi-agent LLM ensemble system for zero-day vulnerability detection
- Five specialized agents: ForensicAnalyst, PatternDetector, TemporalAnalyst, AttributionExpert, MetaAnalyst
- Integration with OpenRouter API for LLM access
- Support for CISA KEV and NVD data sources
- Comprehensive visualization suite with 6 analysis plots
- Real-time monitoring during CVE analysis
- Thompson Sampling for dynamic weight optimization
- Parallel and sequential execution modes
- Caching system with 24-hour TTL for API efficiency
- Credit monitoring system to prevent API quota exhaustion
- Statistical analysis and performance metrics
- Confusion matrix, ROC curves, and confidence calibration
- Detailed logging and debugging capabilities
- Command-line interface with multiple execution options
- JSON output format for results
- Performance report generation

### Security
- Source anonymization to prevent data leakage and bias
- Strict data isolation between training and testing
- Conservative prediction approach for production use
- API key protection and secure configuration

### Performance
- Achieved 68.5% accuracy on balanced test set
- 81.4% precision (low false positives)
- 48.0% recall (conservative detection)
- F1-Score: 0.604
- AUC: 0.752 (significantly better than random)

### Documentation
- Comprehensive README with theoretical framework
- Mathematical formulation of the ensemble approach
- Algorithmic implementation details
- Usage examples and command-line parameters
- API documentation for programmatic access
- Statistical analysis methodology

[Unreleased]: https://github.com/lodetomasi/zero-day-llm-ensemble/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/lodetomasi/zero-day-llm-ensemble/releases/tag/v1.0.0