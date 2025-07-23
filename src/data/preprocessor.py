"""
Data preprocessing and validation for Zero-Day Detection
"""
import re
from typing import Dict, Any, List, Optional, Tuple
import pandas as pd
import numpy as np
from datetime import datetime

from src.utils.logger import get_logger

logger = get_logger(__name__)


class DataPreprocessor:
    """Preprocess and validate CVE data"""
    
    def __init__(self):
        self.validation_stats = {
            'total_processed': 0,
            'valid_entries': 0,
            'invalid_entries': 0,
            'missing_fields': {},
            'data_issues': []
        }
    
    def validate_entry(self, entry: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a single CVE entry"""
        issues = []
        
        # Required fields
        required_fields = ['cve_id', 'description', 'source', 'is_zero_day']
        for field in required_fields:
            if field not in entry or not entry[field]:
                issues.append(f"Missing required field: {field}")
        
        # Validate CVE ID format
        if 'cve_id' in entry:
            if not re.match(r'^CVE-\d{4}-\d{4,}$', entry['cve_id']):
                issues.append(f"Invalid CVE ID format: {entry['cve_id']}")
        
        # Validate year
        if 'year' in entry:
            try:
                year = int(entry['year'])
                if year < 1999 or year > datetime.now().year + 1:
                    issues.append(f"Invalid year: {year}")
            except (ValueError, TypeError):
                issues.append(f"Year must be numeric: {entry.get('year')}")
        
        # Validate description length
        if 'description' in entry:
            desc_len = len(str(entry['description']))
            if desc_len < 10:
                issues.append(f"Description too short: {desc_len} chars")
            elif desc_len > 10000:
                issues.append(f"Description too long: {desc_len} chars")
        
        # Validate source
        valid_sources = ['CISA_KEV', 'NVD', 'MANUAL', 'FALLBACK']
        if 'source' in entry and entry['source'] not in valid_sources:
            issues.append(f"Invalid source: {entry['source']}")
        
        # Check for data leakage
        if 'description' in entry:
            description_lower = str(entry['description']).lower()
            
            # Direct leakage patterns
            leakage_patterns = [
                r'this is a zero[- ]day',
                r'confirmed zero[- ]day',
                r'not a zero[- ]day',
                r'regular cve',
                r'test.*zero[- ]day'
            ]
            
            for pattern in leakage_patterns:
                if re.search(pattern, description_lower):
                    issues.append(f"Potential data leakage in description: {pattern}")
        
        return len(issues) == 0, issues
    
    def preprocess_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Preprocess a single entry"""
        processed = entry.copy()
        
        # Clean text fields
        text_fields = ['description', 'vendor', 'product', 'vulnerability_name']
        for field in text_fields:
            if field in processed and processed[field]:
                # Remove excessive whitespace
                processed[field] = ' '.join(str(processed[field]).split())
                
                # Remove potential artifacts
                processed[field] = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', processed[field])
        
        # Normalize vendor names
        if 'vendor' in processed:
            processed['vendor_normalized'] = self._normalize_vendor(processed['vendor'])
        
        # Extract additional features
        if 'description' in processed:
            processed['description_length'] = len(processed['description'])
            processed['has_cvss'] = 'cvss' in processed['description'].lower()
            processed['has_exploit_mention'] = any(
                term in processed['description'].lower() 
                for term in ['exploit', 'attack', 'vulnerable']
            )
        
        # Ensure boolean type for is_zero_day
        if 'is_zero_day' in processed:
            processed['is_zero_day'] = bool(processed['is_zero_day'])
        
        return processed
    
    def _normalize_vendor(self, vendor: str) -> str:
        """Normalize vendor names for consistency"""
        if not vendor:
            return 'unknown'
        
        vendor_lower = vendor.lower().strip()
        
        # Common normalizations
        normalizations = {
            'microsoft corporation': 'microsoft',
            'microsoft corp': 'microsoft',
            'apple inc': 'apple',
            'apple inc.': 'apple',
            'google llc': 'google',
            'google inc': 'google',
            'adobe systems': 'adobe',
            'oracle corporation': 'oracle',
            'cisco systems': 'cisco',
            'cisco systems inc': 'cisco'
        }
        
        return normalizations.get(vendor_lower, vendor_lower)
    
    def preprocess_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """Preprocess entire dataset"""
        logger.info(f"Preprocessing dataset with {len(df)} entries")
        
        # Reset stats
        self.validation_stats = {
            'total_processed': len(df),
            'valid_entries': 0,
            'invalid_entries': 0,
            'missing_fields': {},
            'data_issues': []
        }
        
        processed_rows = []
        
        for idx, row in df.iterrows():
            entry = row.to_dict()
            
            # Validate
            is_valid, issues = self.validate_entry(entry)
            
            if not is_valid:
                self.validation_stats['invalid_entries'] += 1
                for issue in issues:
                    self.validation_stats['data_issues'].append({
                        'index': idx,
                        'cve_id': entry.get('cve_id', 'Unknown'),
                        'issue': issue
                    })
                
                # Skip invalid entries
                if len(issues) > 2:  # Too many issues
                    logger.warning(f"Skipping entry {idx} due to validation issues: {issues}")
                    continue
            else:
                self.validation_stats['valid_entries'] += 1
            
            # Preprocess
            processed_entry = self.preprocess_entry(entry)
            processed_rows.append(processed_entry)
        
        # Create processed DataFrame
        processed_df = pd.DataFrame(processed_rows)
        
        # Add temporal features
        processed_df = self._add_temporal_features(processed_df)
        
        # Handle missing values
        processed_df = self._handle_missing_values(processed_df)
        
        # Log preprocessing statistics
        logger.info(f"Preprocessing complete:")
        logger.info(f"  Valid entries: {self.validation_stats['valid_entries']}")
        logger.info(f"  Invalid entries: {self.validation_stats['invalid_entries']}")
        logger.info(f"  Final dataset size: {len(processed_df)}")
        
        if self.validation_stats['data_issues']:
            logger.warning(f"  Data issues found: {len(self.validation_stats['data_issues'])}")
        
        return processed_df
    
    def _add_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add temporal features to dataset"""
        current_year = datetime.now().year
        
        if 'year' in df.columns:
            df['years_since_disclosure'] = current_year - df['year']
            df['is_recent'] = df['year'] >= (current_year - 2)
            df['is_very_recent'] = df['year'] >= current_year
        
        # Parse dates if available
        date_columns = ['published_date', 'last_modified', 'date_added']
        for col in date_columns:
            if col in df.columns:
                try:
                    df[f'{col}_parsed'] = pd.to_datetime(df[col], errors='coerce')
                    df[f'{col}_year'] = df[f'{col}_parsed'].dt.year
                    df[f'{col}_month'] = df[f'{col}_parsed'].dt.month
                except Exception as e:
                    logger.debug(f"Could not parse {col}: {e}")
        
        return df
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values appropriately"""
        # Text fields - fill with empty string
        text_fields = ['description', 'vendor', 'product', 'notes', 'vulnerability_name']
        for field in text_fields:
            if field in df.columns:
                df[field] = df[field].fillna('')
        
        # Numeric fields - fill with appropriate defaults
        if 'cvss_score' in df.columns:
            df['cvss_score'] = df['cvss_score'].fillna(0.0)
        
        if 'year' in df.columns:
            df['year'] = df['year'].fillna(datetime.now().year)
        
        # Boolean fields
        if 'is_zero_day' in df.columns:
            df['is_zero_day'] = df['is_zero_day'].fillna(False)
        
        return df
    
    def check_data_leakage(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Check for potential data leakage"""
        logger.info("Checking for data leakage...")
        
        leakage_report = {
            'has_leakage': False,
            'leakage_instances': [],
            'suspicious_patterns': []
        }
        
        # Check for direct label leakage in text fields
        text_fields = ['description', 'notes', 'vulnerability_name']
        leakage_terms = ['zero-day', 'zero day', '0-day', 'not zero-day', 'regular cve']
        
        for field in text_fields:
            if field not in df.columns:
                continue
                
            for idx, value in df[field].items():
                if pd.isna(value):
                    continue
                    
                value_lower = str(value).lower()
                for term in leakage_terms:
                    if term in value_lower:
                        leakage_report['has_leakage'] = True
                        leakage_report['leakage_instances'].append({
                            'index': idx,
                            'field': field,
                            'term': term,
                            'context': value_lower[max(0, value_lower.index(term)-50):value_lower.index(term)+50]
                        })
        
        # Check for suspicious correlations
        if 'source' in df.columns and 'is_zero_day' in df.columns:
            source_correlation = df.groupby('source')['is_zero_day'].mean()
            
            for source, zero_day_rate in source_correlation.items():
                if zero_day_rate == 1.0 or zero_day_rate == 0.0:
                    leakage_report['suspicious_patterns'].append({
                        'type': 'perfect_correlation',
                        'source': source,
                        'zero_day_rate': zero_day_rate
                    })
        
        if leakage_report['has_leakage']:
            logger.warning(f"Data leakage detected: {len(leakage_report['leakage_instances'])} instances")
        else:
            logger.info("No data leakage detected")
        
        return leakage_report
    
    def get_preprocessing_report(self) -> Dict[str, Any]:
        """Get detailed preprocessing report"""
        return {
            'validation_stats': self.validation_stats,
            'preprocessing_timestamp': datetime.now().isoformat()
        }