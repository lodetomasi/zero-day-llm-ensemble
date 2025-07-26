# Changelog

All notable changes to the Zero-Day LLM Ensemble project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial changelog implementation

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