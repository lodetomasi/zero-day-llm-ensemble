# Data Directory

## Main Datasets

### 📊 `extended_dataset.json` (40 CVEs)
Original dataset used in the academic paper:
- 20 verified zero-day vulnerabilities
- 20 regular (non zero-day) vulnerabilities
- Includes CVEs from 2014-2024

### 📈 `expanded_dataset_60.json` (60 CVEs)  
Extended dataset for larger-scale testing:
- 30 verified zero-day vulnerabilities
- 30 regular vulnerabilities
- Additional recent CVEs (2022-2024)

### 📋 `dataset_summary.json`
Metadata about the datasets including counts and verification status.

### 🔍 `expanded_dataset_summary.json`
Detailed listing of all CVEs in the expanded dataset with categorization.

## Cache Directory (`cache/`)

### `cisa_kev_data.json`
CISA Known Exploited Vulnerabilities catalog entries.

### `nvd_regular_cves.json`
Additional regular CVEs from NVD for testing.

## Evidence Directory (`raw_evidence/`)
Pre-collected raw evidence for 37 CVEs including:
- NVD data
- CISA KEV status
- GitHub PoCs
- News mentions
- Threat intelligence

## Scraping Cache (`scraping_cache/`)
Cached web scraping results to avoid repeated API calls and improve performance.

## Archive Directory (`archive/`)
Older datasets and test batches kept for reference but not actively used.

## Data Quality
All zero-day classifications have been verified against multiple public sources including:
- CISA KEV listings
- Security vendor reports
- Public exploit databases
- Academic research papers
- Threat intelligence reports

Ground truth corrections were applied to ensure accuracy and avoid data leakage in the academic evaluation.