#!/usr/bin/env python3
"""Fixed version: Test with proper evidence integration and calibrated thresholds"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.data.preprocessor import DataPreprocessor
from src.ensemble.multi_agent import MultiAgentSystem
from src.scraping.comprehensive_scraper import ComprehensiveZeroDayScraper
from src.scraping.enhanced_temporal_analyzer import TemporalAnalyzer
from src.utils.logger import get_logger
import json
import random
from datetime import datetime
import time

logger = get_logger(__name__)

class ImprovedMonitor:
    """Enhanced monitor with uncertainty tracking"""
    def __init__(self):
        self.predictions = []
        self.start_time = time.time()
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.uncertain = 0  # New: track uncertain cases
        self.with_evidence = 0
        self.without_evidence = 0
    
    def update(self, actual, predicted, probability, has_evidence, uncertainty=None):
        """Update statistics with new prediction"""
        self.predictions.append({
            'actual': actual,
            'predicted': predicted,
            'probability': probability,
            'has_evidence': has_evidence,
            'uncertainty': uncertainty,
            'timestamp': time.time() - self.start_time
        })
        
        if has_evidence:
            self.with_evidence += 1
        else:
            self.without_evidence += 1
        
        # Update confusion matrix only for confident predictions
        if uncertainty and uncertainty > 0.3:  # High uncertainty threshold
            self.uncertain += 1
        else:
            if actual and predicted:
                self.tp += 1
            elif not actual and predicted:
                self.fp += 1
            elif not actual and not predicted:
                self.tn += 1
            else:
                self.fn += 1
    
    def get_metrics(self):
        """Calculate current metrics"""
        total = self.tp + self.fp + self.tn + self.fn
        if total == 0:
            return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
        
        accuracy = (self.tp + self.tn) / total
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'uncertain_rate': self.uncertain / (total + self.uncertain) if (total + self.uncertain) > 0 else 0,
            'evidence_rate': self.with_evidence / (self.with_evidence + self.without_evidence) if (self.with_evidence + self.without_evidence) > 0 else 0
        }

def calculate_calibrated_score(evidence, llm_score):
    """
    Calculate a properly calibrated final score based on evidence and LLM assessment
    """
    # Start with conservative baseline
    base_score = 0.3
    
    # Evidence-based adjustments
    evidence_adjustments = 0.0
    
    # Strong positive indicators
    if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
        evidence_adjustments += 0.25  # CISA KEV is strong signal
        
        # Extra boost if added quickly after disclosure
        if evidence['indicators'].get('rapid_kev_addition'):
            evidence_adjustments += 0.15
    
    # News mentions
    news_mentions = evidence['sources'].get('security_news', {}).get('zero_day_mentions', 0)
    if news_mentions > 0:
        evidence_adjustments += min(0.15 * news_mentions, 0.3)  # Cap at 0.3
    
    # APT associations
    apt_groups = evidence['indicators'].get('apt_associations', [])
    if apt_groups:
        evidence_adjustments += min(0.1 * len(apt_groups), 0.2)  # Cap at 0.2
    
    # Emergency patches
    if evidence['indicators'].get('emergency_patches'):
        evidence_adjustments += 0.1
    
    # Exploitation timeline
    if evidence['indicators'].get('exploitation_before_patch'):
        evidence_adjustments += 0.2
    
    # Negative indicators (penalties)
    github_pocs = evidence['sources'].get('github', {}).get('poc_count', 0)
    if github_pocs > 50:  # Too many PoCs = not zero-day
        evidence_adjustments -= 0.3
    elif github_pocs > 20:
        evidence_adjustments -= 0.15
    
    # Coordinated disclosure
    if evidence['indicators'].get('coordinated_disclosure'):
        evidence_adjustments -= 0.2
    
    # Long time between disclosure and KEV
    if evidence['indicators'].get('delayed_kev_addition'):
        evidence_adjustments -= 0.1
    
    # Combine base + evidence
    evidence_score = base_score + evidence_adjustments
    
    # Weight: 60% evidence, 40% LLM when we have good evidence
    # More weight to LLM when evidence is scarce
    evidence_quality = min(abs(evidence_adjustments), 1.0)  # 0-1 scale
    
    if evidence_quality > 0.3:  # Good evidence
        final_score = 0.6 * evidence_score + 0.4 * llm_score
    else:  # Poor evidence
        final_score = 0.3 * evidence_score + 0.7 * llm_score
    
    # Calculate uncertainty
    uncertainty = 1.0 - evidence_quality
    
    # Clamp to [0, 1]
    final_score = max(0.0, min(1.0, final_score))
    
    return final_score, uncertainty, evidence_quality

def load_dataset(zero_days_count, regular_count):
    """Load CVEs from pre-downloaded dataset"""
    dataset_dir = Path("data/enriched_dataset")
    
    # Try enriched dataset first
    if dataset_dir.exists():
        zero_day_file = dataset_dir / "enriched_zero_days.json"
        regular_file = dataset_dir / "enriched_regular_cves.json"
        
        if zero_day_file.exists() and regular_file.exists():
            with open(zero_day_file, 'r') as f:
                all_zero_days = json.load(f)
            with open(regular_file, 'r') as f:
                all_regular = json.load(f)
            print("✅ Using enriched dataset with pre-collected evidence")
        else:
            # Fallback to basic dataset
            dataset_dir = Path("data/test_dataset")
            zero_day_file = dataset_dir / "zero_day_cves.json"
            regular_file = dataset_dir / "regular_cves.json"
            
            with open(zero_day_file, 'r') as f:
                all_zero_days = json.load(f)
            with open(regular_file, 'r') as f:
                all_regular = json.load(f)
            print("⚠️  Using basic dataset (no pre-collected evidence)")
    else:
        print("❌ No dataset found! Run download scripts first.")
        sys.exit(1)
    
    # Sample requested amounts
    zero_days = random.sample(all_zero_days, min(zero_days_count, len(all_zero_days)))
    regular = random.sample(all_regular, min(regular_count, len(all_regular)))
    
    print(f"  Loaded {len(zero_days)} zero-days (available: {len(all_zero_days)})")
    print(f"  Loaded {len(regular)} regular CVEs (available: {len(all_regular)})")
    
    return zero_days, regular

def main():
    parser = argparse.ArgumentParser(description='Fixed test with proper evidence handling')
    parser.add_argument('--zero-days', type=int, default=10, help='Number of zero-days')
    parser.add_argument('--regular', type=int, default=10, help='Number of regular CVEs')
    parser.add_argument('--parallel', action='store_true', help='Run agents in parallel')
    parser.add_argument('--use-cache', action='store_true', help='Use cached evidence if available')
    args = parser.parse_args()
    
    print("🚀 Zero-Day Detection Test (FIXED VERSION)")
    print("=" * 60)
    print(f"Zero-days: {args.zero_days}")
    print(f"Regular CVEs: {args.regular}")
    print(f"Total samples: {args.zero_days + args.regular}")
    print(f"Parallel execution: {args.parallel}")
    print(f"Use cache: {args.use_cache}")
    print("=" * 60)
    
    # Load dataset
    print("\n📊 Loading dataset...")
    zero_days, regular_cves = load_dataset(args.zero_days, args.regular)
    
    # Initialize
    preprocessor = DataPreprocessor()
    monitor = ImprovedMonitor()
    
    # Preprocess and combine
    print("\n🔧 Preprocessing data...")
    all_data = []
    
    for cve in zero_days:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = True
            # Include any pre-collected evidence
            if 'evidence' in cve:
                processed['cached_evidence'] = cve['evidence']
            all_data.append(processed)
    
    for cve in regular_cves:
        processed = preprocessor.preprocess_entry(cve)
        if processed:
            processed['is_zero_day'] = False
            if 'evidence' in cve:
                processed['cached_evidence'] = cve['evidence']
            all_data.append(processed)
    
    random.shuffle(all_data)
    print(f"  ✓ Total samples ready: {len(all_data)}")
    
    # Initialize systems
    print("\n🤖 Initializing enhanced system...")
    llm_system = MultiAgentSystem(
        use_thompson_sampling=False,
        parallel_execution=args.parallel
    )
    scraper = ComprehensiveZeroDayScraper()
    temporal_analyzer = TemporalAnalyzer()
    
    # Run analysis
    print("\n🔍 Analyzing CVEs with PROPER evidence integration...")
    print("-" * 60)
    
    results = []
    
    for i, cve_data in enumerate(all_data, 1):
        cve_id = cve_data['cve_id']
        is_zero_day = cve_data['is_zero_day']
        
        print(f"\n[{i}/{len(all_data)}] {cve_id} ({'Zero-day' if is_zero_day else 'Regular'})")
        
        has_evidence = False
        uncertainty = 0.5  # Default high uncertainty
        
        try:
            # Step 1: Get evidence (from cache or fresh scraping)
            if args.use_cache and 'cached_evidence' in cve_data:
                print(f"  📂 Using cached evidence...")
                evidence = cve_data['cached_evidence']
                has_evidence = True
            else:
                print(f"  📡 Collecting fresh evidence...")
                evidence = scraper.scrape_all_sources(cve_id)
                
                # Add temporal analysis
                timeline_analysis = temporal_analyzer.analyze_timeline(evidence)
                evidence['timeline_analysis'] = timeline_analysis
                
                has_evidence = True
            
            print(f"  ✓ Evidence ready (sources: {len(evidence.get('sources', {}))})")
            
            # Step 2: Build evidence context for LLM
            evidence_summary = build_evidence_summary(evidence)
            
            # Add evidence to CVE description
            enriched_cve_data = cve_data.copy()
            enriched_cve_data['description'] = enriched_cve_data.get('description', '') + "\n\n" + evidence_summary
            
            # Step 3: LLM analysis with evidence
            print(f"  🤖 Running LLM ensemble analysis...")
            llm_result = llm_system.analyze_vulnerability(enriched_cve_data, verbose=False)
            llm_score = llm_result.get('ensemble', {}).get('prediction', 0.5)
            
            # Step 4: Calculate calibrated score
            final_score, uncertainty, evidence_quality = calculate_calibrated_score(evidence, llm_score)
            
            print(f"  📊 Scores:")
            print(f"     - LLM ensemble: {llm_score:.1%}")
            print(f"     - Evidence quality: {evidence_quality:.1%}")
            print(f"     - Final calibrated: {final_score:.1%}")
            print(f"     - Uncertainty: {uncertainty:.1%}")
            
        except Exception as e:
            logger.error(f"Error analyzing {cve_id}: {e}")
            print(f"  ⚠️ Analysis failed: {str(e)[:100]}...")
            
            # When analysis fails, mark as uncertain
            final_score = 0.5
            uncertainty = 1.0  # Maximum uncertainty
            has_evidence = False
        
        # Step 5: Make decision based on uncertainty
        if uncertainty > 0.7:
            # Too uncertain - should ideally defer to human
            print(f"  ⚠️ HIGH UNCERTAINTY - Requires human review")
            # For testing, we'll use a conservative threshold
            is_zero_day_pred = final_score >= 0.7
        else:
            # Normal threshold with calibrated score
            threshold = 0.55  # Slightly above midpoint
            is_zero_day_pred = final_score >= threshold
        
        print(f"  → Prediction: {'Zero-day' if is_zero_day_pred else 'Regular'} ({'CORRECT' if is_zero_day == is_zero_day_pred else 'WRONG'})")
        
        # Update monitor
        monitor.update(is_zero_day, is_zero_day_pred, final_score, has_evidence, uncertainty)
        
        # Save result
        results.append({
            'cve_id': cve_id,
            'actual': is_zero_day,
            'predicted': is_zero_day_pred,
            'final_score': final_score,
            'llm_score': llm_score if 'llm_score' in locals() else None,
            'uncertainty': uncertainty,
            'evidence_collected': has_evidence,
            'correct': is_zero_day == is_zero_day_pred
        })
        
        # Print progress stats every 5 CVEs
        if i % 5 == 0:
            metrics = monitor.get_metrics()
            print(f"\n📊 Progress [{i}/{len(all_data)}]:")
            print(f"  Accuracy:  {metrics['accuracy']:.1%}")
            print(f"  Precision: {metrics['precision']:.1%}")
            print(f"  Recall:    {metrics['recall']:.1%}")
            print(f"  Evidence rate: {metrics['evidence_rate']:.1%}")
            print(f"  Uncertain: {metrics['uncertain_rate']:.1%}")
    
    # Final results
    metrics = monitor.get_metrics()
    
    print("\n" + "=" * 60)
    print("📊 FINAL RESULTS (FIXED VERSION)")
    print("=" * 60)
    
    cm = {
        'tp': monitor.tp, 'fp': monitor.fp,
        'tn': monitor.tn, 'fn': monitor.fn,
        'uncertain': monitor.uncertain
    }
    
    print(f"\n🎯 Confusion Matrix:")
    print(f"                 Predicted")
    print(f"              Zero-day  Regular  Uncertain")
    print(f"Actual Zero-day   {cm['tp']:3d}      {cm['fn']:3d}       {'-':>3}")
    print(f"       Regular    {cm['fp']:3d}      {cm['tn']:3d}       {'-':>3}")
    print(f"       Total uncertain: {cm['uncertain']}")
    
    print(f"\n📊 Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.1%}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall:    {metrics['recall']:.1%}")
    print(f"  F1 Score:  {metrics['f1']:.3f}")
    print(f"\n📡 Evidence Collection:")
    print(f"  Success rate: {metrics['evidence_rate']:.1%}")
    print(f"  Uncertain predictions: {metrics['uncertain_rate']:.1%}")
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path('results')
    results_file = output_dir / f'fixed_test_{timestamp}.json'
    
    with open(results_file, 'w') as f:
        json.dump({
            'test_type': 'fixed_evidence_integration',
            'timestamp': timestamp,
            'samples': {
                'zero_days': monitor.tp + monitor.fn,
                'regular': monitor.tn + monitor.fp,
                'uncertain': monitor.uncertain,
                'total': len(results)
            },
            'confusion_matrix': cm,
            'metrics': metrics,
            'evidence_stats': {
                'with_evidence': monitor.with_evidence,
                'without_evidence': monitor.without_evidence
            },
            'predictions': results
        }, f, indent=2)
    
    print(f"\n💾 Results saved to: {results_file}")
    
    # Recommendations
    print("\n🔍 Analysis Summary:")
    if metrics['precision'] < 0.7:
        print("  ⚠️ Low precision - too many false positives")
        print("     → Consider increasing threshold or requiring more evidence")
    if metrics['recall'] < 0.7:
        print("  ⚠️ Low recall - missing real zero-days")
        print("     → Consider lowering threshold or improving evidence sources")
    if metrics['uncertain_rate'] > 0.2:
        print("  ⚠️ High uncertainty rate")
        print("     → Need better evidence sources or more training data")
    if metrics['accuracy'] >= 0.75:
        print("  ✅ Good overall accuracy!")
    
    print("\n✅ Test completed successfully!")

def build_evidence_summary(evidence):
    """Build a structured summary of evidence for LLM consumption"""
    summary = "EVIDENCE FROM WEB SOURCES:\n"
    
    # CISA KEV status
    if evidence['sources'].get('cisa_kev', {}).get('in_kev'):
        kev_data = evidence['sources']['cisa_kev']
        summary += "- ⚠️ LISTED IN CISA KNOWN EXPLOITED VULNERABILITIES CATALOG\n"
        if kev_data.get('date_added'):
            summary += f"  - Added to KEV: {kev_data['date_added']}\n"
        if kev_data.get('description'):
            summary += f"  - KEV Description: {kev_data['description']}\n"
    else:
        summary += "- ✅ NOT in CISA KEV catalog\n"
    
    # Security news
    news_mentions = evidence['sources'].get('security_news', {}).get('zero_day_mentions', 0)
    if news_mentions > 0:
        summary += f"- 📰 Found {news_mentions} security articles mentioning zero-day exploitation\n"
        articles = evidence['sources'].get('security_news', {}).get('articles', [])
        for article in articles[:3]:  # Top 3
            if 'zero-day' in article.get('title', '').lower():
                summary += f"  - \"{article['title']}\"\n"
    
    # APT associations
    apt_groups = evidence['indicators'].get('apt_associations', [])
    if apt_groups:
        summary += f"- 🎯 Associated with {len(apt_groups)} APT group(s):\n"
        for apt in apt_groups[:3]:
            summary += f"  - {apt['group']}: {apt.get('campaign', 'Unknown campaign')}\n"
    
    # GitHub PoCs
    github_data = evidence['sources'].get('github', {})
    poc_count = github_data.get('poc_count', 0)
    if poc_count > 0:
        summary += f"- 💻 Found {poc_count} proof-of-concept repositories\n"
        if poc_count > 50:
            summary += "  - ⚠️ HIGH number of PoCs suggests NOT a zero-day\n"
    
    # Timeline analysis
    timeline = evidence.get('timeline_analysis', {})
    if timeline.get('analysis'):
        summary += f"- 📅 Timeline Analysis:\n"
        summary += f"  {timeline['analysis']}\n"
        if timeline.get('confidence', 0) > 0:
            summary += f"  - Zero-day confidence from timeline: {timeline['confidence']:.0%}\n"
    
    # Exploitation indicators
    if evidence['indicators'].get('exploitation_before_patch'):
        summary += "- 🚨 STRONG EVIDENCE of exploitation BEFORE patch\n"
    
    if evidence['indicators'].get('emergency_patches'):
        summary += "- 🔧 Emergency/out-of-band patches released\n"
    
    if evidence['indicators'].get('coordinated_disclosure'):
        summary += "- 📝 Evidence of coordinated disclosure (less likely zero-day)\n"
    
    # Metasploit/ExploitDB
    if evidence['sources'].get('exploit_timeline', {}).get('metasploit_module'):
        summary += "- 🔨 Metasploit module available\n"
    
    return summary

if __name__ == "__main__":
    main()