#!/usr/bin/env python3
"""
Bulk CVE Testing Script for Zero-Day Detection System
Tests multiple CVEs and generates a comprehensive report
"""

import json
import time
import random
from datetime import datetime
from typing import List, Dict, Tuple
import pandas as pd
from pathlib import Path
import concurrent.futures
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.detect_zero_days_enhanced import EnhancedZeroDayDetector
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

class BulkCVETester:
    def __init__(self, max_workers: int = 2):
        """Initialize bulk tester with concurrent processing"""
        self.detector = EnhancedZeroDayDetector(use_turbo=True)
        self.max_workers = max_workers
        self.results = []
        
    def get_test_cves(self, count: int = 100) -> List[Dict[str, any]]:
        """
        Get a list of CVEs to test
        Mix of known zero-days and regular vulnerabilities
        """
        # Known zero-days from CISA KEV
        known_zero_days = [
            "CVE-2024-3400",  # Palo Alto Networks
            "CVE-2021-44228", # Log4j
            "CVE-2023-20198", # Cisco IOS XE
            "CVE-2023-3519",  # Citrix ADC
            "CVE-2023-2868",  # Barracuda ESG
            "CVE-2023-27350", # PaperCut
            "CVE-2023-34362", # MOVEit Transfer
            "CVE-2022-40684", # Fortinet
            "CVE-2022-41040", # Exchange ProxyNotShell
            "CVE-2022-41082", # Exchange ProxyNotShell
            "CVE-2022-26134", # Confluence
            "CVE-2022-1388",  # F5 BIG-IP
            "CVE-2021-40539", # Zoho ManageEngine
            "CVE-2021-34527", # PrintNightmare
            "CVE-2021-21972", # VMware vCenter
            "CVE-2021-26855", # Exchange ProxyLogon
            "CVE-2020-1472",  # Zerologon
            "CVE-2019-19781", # Citrix ADC
            "CVE-2019-11510", # Pulse Secure VPN
            "CVE-2017-11882", # Microsoft Office
        ]
        
        # Recent CVEs (mix of severities)
        recent_cves = []
        current_year = datetime.now().year
        
        # Generate recent CVE IDs
        for year in range(current_year - 2, current_year + 1):
            for i in range(1, 40):
                cve_id = f"CVE-{year}-{random.randint(1000, 30000)}"
                recent_cves.append(cve_id)
        
        # Combine lists
        all_cves = []
        
        # Add all known zero-days
        for cve in known_zero_days[:min(20, count//3)]:
            all_cves.append({
                "cve_id": cve,
                "expected_zero_day": True,
                "category": "known_zero_day"
            })
        
        # Add random recent CVEs
        random.shuffle(recent_cves)
        remaining = count - len(all_cves)
        for cve in recent_cves[:remaining]:
            all_cves.append({
                "cve_id": cve,
                "expected_zero_day": False,  # Most will be false
                "category": "recent_cve"
            })
        
        # Shuffle to mix categories
        random.shuffle(all_cves)
        
        return all_cves[:count]
    
    def test_single_cve(self, cve_info: Dict) -> Dict:
        """Test a single CVE and return results"""
        cve_id = cve_info["cve_id"]
        start_time = time.time()
        
        try:
            logger.info(f"Testing {cve_id}...")
            result = self.detector.detect_zero_day(cve_id, verbose=False)
            
            elapsed = time.time() - start_time
            
            return {
                "cve_id": cve_id,
                "is_zero_day_detected": result["is_zero_day"],
                "expected_zero_day": cve_info["expected_zero_day"],
                "category": cve_info["category"],
                "detection_score": result["detection_score"],
                "confidence": result["confidence"],
                "confidence_level": result["confidence_level"],
                "cisa_kev": result["evidence_summary"].get("cisa_kev", False),
                "agent_consensus": result["agent_consensus"],
                "data_quality": result["evidence_summary"]["data_quality_score"],
                "processing_time": elapsed,
                "error": None,
                "correct_detection": result["is_zero_day"] == cve_info["expected_zero_day"]
            }
            
        except Exception as e:
            logger.error(f"Error testing {cve_id}: {str(e)}")
            elapsed = time.time() - start_time
            
            return {
                "cve_id": cve_id,
                "is_zero_day_detected": None,
                "expected_zero_day": cve_info["expected_zero_day"],
                "category": cve_info["category"],
                "detection_score": None,
                "confidence": None,
                "confidence_level": None,
                "cisa_kev": None,
                "agent_consensus": None,
                "data_quality": None,
                "processing_time": elapsed,
                "error": str(e),
                "correct_detection": None
            }
    
    def run_bulk_test(self, cve_count: int = 100, save_results: bool = True) -> pd.DataFrame:
        """Run bulk testing on multiple CVEs"""
        print(f"\n🔬 Starting bulk test of {cve_count} CVEs")
        print("=" * 60)
        
        # Get test CVEs
        test_cves = self.get_test_cves(cve_count)
        logger.info(f"Testing {len(test_cves)} CVEs ({sum(1 for c in test_cves if c['expected_zero_day'])} expected zero-days)")
        
        # Run tests with progress tracking
        results = []
        start_time = time.time()
        
        # Process in batches to avoid overwhelming the API
        batch_size = 5
        for i in range(0, len(test_cves), batch_size):
            batch = test_cves[i:i+batch_size]
            batch_results = []
            
            # Process batch concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_cve = {executor.submit(self.test_single_cve, cve): cve for cve in batch}
                
                for future in concurrent.futures.as_completed(future_to_cve):
                    result = future.result()
                    batch_results.append(result)
                    
                    # Print progress
                    completed = len(results) + len(batch_results)
                    print(f"\rProgress: {completed}/{len(test_cves)} ({completed/len(test_cves)*100:.1f}%)", end="")
            
            results.extend(batch_results)
            
            # Small delay between batches to avoid rate limiting
            if i + batch_size < len(test_cves):
                time.sleep(2)
        
        print()  # New line after progress
        
        # Convert to DataFrame
        df = pd.DataFrame(results)
        
        # Calculate statistics
        total_time = time.time() - start_time
        self._print_statistics(df, total_time)
        
        # Save results if requested
        if save_results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save detailed results
            csv_path = f"bulk_test_results_{timestamp}.csv"
            df.to_csv(csv_path, index=False)
            logger.info(f"Results saved to {csv_path}")
            
            # Save summary report
            report_path = f"bulk_test_report_{timestamp}.json"
            self._save_report(df, total_time, report_path)
            logger.info(f"Report saved to {report_path}")
        
        return df
    
    def _print_statistics(self, df: pd.DataFrame, total_time: float):
        """Print test statistics"""
        print("\n" + "=" * 60)
        print("📊 TEST RESULTS SUMMARY")
        print("=" * 60)
        
        # Overall accuracy
        valid_results = df[df['correct_detection'].notna()]
        if len(valid_results) > 0:
            accuracy = (valid_results['correct_detection'].sum() / len(valid_results)) * 100
            print(f"\n✅ Overall Accuracy: {accuracy:.1f}%")
        
        # Detection stats
        print(f"\n🔍 Detection Statistics:")
        print(f"   Total CVEs tested: {len(df)}")
        print(f"   Successful tests: {len(df[df['error'].isna()])}")
        print(f"   Failed tests: {len(df[df['error'].notna()])}")
        
        # Zero-day detection
        detected_zd = df[df['is_zero_day_detected'] == True]
        print(f"\n🎯 Zero-Day Detection:")
        print(f"   Total detected as zero-days: {len(detected_zd)}")
        
        # Expected zero-days
        expected_zd = df[df['expected_zero_day'] == True]
        if len(expected_zd) > 0:
            true_positives = len(expected_zd[expected_zd['is_zero_day_detected'] == True])
            false_negatives = len(expected_zd[expected_zd['is_zero_day_detected'] == False])
            print(f"   True positives: {true_positives}/{len(expected_zd)}")
            print(f"   False negatives: {false_negatives}/{len(expected_zd)}")
        
        # Non zero-days
        expected_non_zd = df[df['expected_zero_day'] == False]
        if len(expected_non_zd) > 0:
            true_negatives = len(expected_non_zd[expected_non_zd['is_zero_day_detected'] == False])
            false_positives = len(expected_non_zd[expected_non_zd['is_zero_day_detected'] == True])
            print(f"\n📈 Regular CVE Detection:")
            print(f"   True negatives: {true_negatives}/{len(expected_non_zd)}")
            print(f"   False positives: {false_positives}/{len(expected_non_zd)}")
        
        # Performance metrics
        print(f"\n⚡ Performance Metrics:")
        print(f"   Total processing time: {total_time:.1f}s")
        print(f"   Average time per CVE: {df['processing_time'].mean():.1f}s")
        print(f"   Fastest: {df['processing_time'].min():.1f}s")
        print(f"   Slowest: {df['processing_time'].max():.1f}s")
        
        # Confidence analysis
        valid_conf = df[df['confidence'].notna()]
        if len(valid_conf) > 0:
            print(f"\n📊 Confidence Analysis:")
            print(f"   Average confidence: {valid_conf['confidence'].mean():.1f}%")
            print(f"   High confidence: {len(valid_conf[valid_conf['confidence_level'] == 'HIGH'])}")
            print(f"   Medium confidence: {len(valid_conf[valid_conf['confidence_level'] == 'MEDIUM'])}")
            print(f"   Low confidence: {len(valid_conf[valid_conf['confidence_level'] == 'LOW'])}")
    
    def _save_report(self, df: pd.DataFrame, total_time: float, filepath: str):
        """Save detailed report"""
        valid_results = df[df['correct_detection'].notna()]
        
        report = {
            "test_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_cves_tested": len(df),
                "total_processing_time": total_time,
                "average_time_per_cve": df['processing_time'].mean()
            },
            "accuracy_metrics": {
                "overall_accuracy": (valid_results['correct_detection'].sum() / len(valid_results)) * 100 if len(valid_results) > 0 else 0,
                "true_positives": len(df[(df['expected_zero_day'] == True) & (df['is_zero_day_detected'] == True)]),
                "false_positives": len(df[(df['expected_zero_day'] == False) & (df['is_zero_day_detected'] == True)]),
                "true_negatives": len(df[(df['expected_zero_day'] == False) & (df['is_zero_day_detected'] == False)]),
                "false_negatives": len(df[(df['expected_zero_day'] == True) & (df['is_zero_day_detected'] == False)])
            },
            "performance_metrics": {
                "successful_tests": len(df[df['error'].isna()]),
                "failed_tests": len(df[df['error'].notna()]),
                "min_processing_time": df['processing_time'].min(),
                "max_processing_time": df['processing_time'].max(),
                "avg_processing_time": df['processing_time'].mean()
            },
            "confidence_distribution": {
                "high": len(df[df['confidence_level'] == 'HIGH']),
                "medium": len(df[df['confidence_level'] == 'MEDIUM']),
                "low": len(df[df['confidence_level'] == 'LOW']),
                "average_confidence": df['confidence'].mean() if df['confidence'].notna().any() else 0
            },
            "failed_cves": df[df['error'].notna()][['cve_id', 'error']].to_dict('records')
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)


def main():
    """Main function to run bulk testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bulk test CVEs for zero-day detection')
    parser.add_argument('--count', type=int, default=100, help='Number of CVEs to test (default: 100)')
    parser.add_argument('--workers', type=int, default=2, help='Number of concurrent workers (default: 2)')
    parser.add_argument('--no-save', action='store_true', help='Do not save results to file')
    
    args = parser.parse_args()
    
    # Create tester and run
    tester = BulkCVETester(max_workers=args.workers)
    results = tester.run_bulk_test(cve_count=args.count, save_results=not args.no_save)
    
    # Show top detections
    print("\n🏆 Top Zero-Day Detections (by score):")
    top_detections = results[results['is_zero_day_detected'] == True].nlargest(10, 'detection_score')
    for _, row in top_detections.iterrows():
        print(f"   {row['cve_id']}: {row['detection_score']:.1%} (confidence: {row['confidence']:.1f}%)")


if __name__ == "__main__":
    main()