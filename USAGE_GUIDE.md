# Zero-Day LLM Ensemble - Usage Guide

## Table of Contents
1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Web Scraping](#web-scraping)
5. [API Reference](#api-reference)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- OpenRouter API key

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/lodetomasi/zero-day-llm-ensemble.git
cd zero-day-llm-ensemble
```

2. **Create virtual environment (recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up API key**
```bash
export OPENROUTER_API_KEY="your-api-key-here"
```

Or create a `.env` file:
```
OPENROUTER_API_KEY=your-api-key-here
```

## Basic Usage

### Running the Original Test

For the classic multi-agent LLM analysis:

```bash
# Balanced test with 50 zero-days and 50 regular CVEs
python run_complete_test.py --zero-days 50 --regular 50 --parallel

# Smaller test for quick validation
python run_complete_test.py --zero-days 10 --regular 10 --parallel
```

### Running Enhanced Analysis with Web Scraping

For the improved version with web evidence:

```bash
# Analyze specific CVEs
python run_analysis.py CVE-2023-23397 CVE-2021-44228

# Analyze from a file
python run_analysis.py --file cve_list.txt

# Verbose mode for detailed output
python run_analysis.py CVE-2023-23397 -v

# Custom output directory
python run_analysis.py CVE-2023-23397 --output my_results
```

## Advanced Features

### Programmatic Usage

```python
from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper

# Initialize systems
llm_system = MultiAgentSystem(parallel_execution=True)
scraper = ComprehensiveZeroDayScraper()

# Analyze a CVE
cve_data = {
    'cve_id': 'CVE-2023-23397',
    'vendor': 'Microsoft',
    'product': 'Outlook',
    'description': 'Elevation of privilege vulnerability'
}

# Get web evidence
evidence = scraper.scrape_all_sources(cve_data['cve_id'])
print(f"Evidence-based score: {evidence['scores']['zero_day_confidence']:.1%}")

# Get LLM analysis
llm_result = llm_system.analyze_vulnerability(cve_data)
print(f"LLM-based score: {llm_result['ensemble']['prediction']:.1%}")
```

### Custom Agent Configuration

Modify agent models in `config/settings.py`:

```python
AGENT_MODELS = {
    "ForensicAnalyst": "your-preferred-model",
    "PatternDetector": "your-preferred-model",
    # ... other agents
}
```

### Batch Processing

Process multiple CVEs from a file:

```python
# cve_list.txt (one CVE per line)
CVE-2023-23397
CVE-2021-44228
CVE-2024-3400
```

```bash
python run_analysis.py --file cve_list.txt --output batch_results
```

## Web Scraping

### Available Sources

The comprehensive scraper collects evidence from:

1. **Official Sources**
   - CISA Known Exploited Vulnerabilities (KEV)
   - National Vulnerability Database (NVD)
   - Vendor security advisories

2. **Security Media**
   - The Hacker News
   - BleepingComputer
   - SecurityWeek
   - ZDNet Security

3. **Technical Sources**
   - GitHub repositories (PoCs)
   - Exploit-DB
   - Metasploit modules
   - Commercial exploit markets

4. **Community Sources**
   - Reddit security communities
   - Twitter/X security discussions
   - Full Disclosure mailing list

### Scraping Configuration

```python
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper

# Initialize with custom cache directory
scraper = ComprehensiveZeroDayScraper(cache_dir=Path("my_cache"))

# Scrape specific sources only
evidence = scraper.scrape_nvd_details("CVE-2023-23397")
kev_status = scraper.scrape_cisa_kev("CVE-2023-23397")
news = scraper.scrape_security_news("CVE-2023-23397")
```

### Cache Management

Scraped data is cached for 7 days by default:

```bash
# Clear cache
rm -rf data/scraping_cache/

# Custom cache expiry (in code)
scraper.cache_expiry = timedelta(days=14)
```

## API Reference

### MultiAgentSystem

```python
class MultiAgentSystem:
    def __init__(self, parallel_execution=True, timeout=60):
        """Initialize the multi-agent ensemble"""
        
    def analyze_vulnerability(self, cve_data: Dict) -> Dict:
        """Analyze a CVE using all agents"""
        
    def get_agent_predictions(self) -> Dict:
        """Get individual agent predictions"""
```

### ComprehensiveZeroDayScraper

```python
class ComprehensiveZeroDayScraper:
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize scraper with caching"""
        
    def scrape_all_sources(self, cve_id: str) -> Dict:
        """Scrape all available sources"""
        
    def scrape_nvd_details(self, cve_id: str) -> Dict:
        """Get NVD information"""
        
    def scrape_cisa_kev(self, cve_id: str) -> Dict:
        """Check CISA KEV status"""
```

### Output Format

#### Analysis Result
```json
{
  "cve_id": "CVE-2023-23397",
  "is_zero_day": true,
  "scores": {
    "evidence_based": 0.75,
    "llm_based": 0.59,
    "combined": 0.69
  },
  "evidence": { ... },
  "llm_analysis": { ... }
}
```

#### Evidence Structure
```json
{
  "sources": {
    "nvd": { ... },
    "cisa_kev": { "in_kev": true, ... },
    "security_news": { "zero_day_mentions": 3, ... },
    "github": { "poc_repositories": 5, ... }
  },
  "indicators": {
    "exploitation_before_patch": [...],
    "apt_associations": [...],
    "emergency_patches": [...]
  },
  "scores": {
    "zero_day_confidence": 0.75,
    "exploitation_likelihood": 0.80,
    "evidence_quality": 0.85
  }
}
```

## Troubleshooting

### Common Issues

1. **API Key Error**
   ```
   Error: No API key found
   ```
   Solution: Set `OPENROUTER_API_KEY` environment variable

2. **Rate Limiting**
   ```
   Error: 429 Too Many Requests
   ```
   Solution: Add delays between requests or reduce parallel execution

3. **Timeout Errors**
   ```
   Error: Request timeout
   ```
   Solution: Increase timeout in settings or use `--timeout` flag

4. **Cache Issues**
   ```
   Error: Cache corruption
   ```
   Solution: Clear cache directory and retry

### Debug Mode

Enable detailed logging:

```bash
# Set log level
export LOG_LEVEL=DEBUG

# Or in code
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Performance Tips

1. **Use Parallel Execution**
   - Add `--parallel` flag for faster processing
   - Reduces time by ~60%

2. **Leverage Caching**
   - Scraped data is cached for 7 days
   - Repeated analyses are much faster

3. **Batch Processing**
   - Process multiple CVEs at once
   - More efficient than individual requests

4. **Optimize Sources**
   - Disable unnecessary sources if speed is critical
   - Focus on high-value sources (CISA, NVD)

## Examples

### Example 1: Quick Zero-Day Check

```bash
# Single CVE quick check
python run_analysis.py CVE-2023-23397 --verbose
```

### Example 2: Batch Analysis with Report

```bash
# Create CVE list
echo "CVE-2023-23397
CVE-2021-44228
CVE-2024-3400
CVE-2017-0144" > my_cves.txt

# Run analysis
python run_analysis.py --file my_cves.txt --output reports/batch1
```

### Example 3: Custom Integration

```python
# custom_analyzer.py
from src.scraping import create_cve_report

# List of CVEs to analyze
cves = ["CVE-2023-23397", "CVE-2021-44228"]

# Generate reports
for cve in cves:
    report_path = create_cve_report(cve, output_dir=Path("my_reports"))
    print(f"Report saved: {report_path}")
```

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Open an issue on GitHub
3. Contact: lorenzo.detomasi@graduate.univaq.it