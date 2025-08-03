#!/usr/bin/env python3
"""
Intelligence Analysis Script - Academic Version
Focuses on intelligence aggregation and quality metrics rather than binary detection
"""
import argparse
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from src.intelligence.aggregator import IntelligenceAggregator
from src.utils.logger import get_logger
import json
from datetime import datetime
import pandas as pd

logger = get_logger(__name__)


def analyze_cve_intelligence(cve_id: str, verbose: bool = False):
    """
    Analyze CVE and generate intelligence report
    
    Args:
        cve_id: CVE identifier
        verbose: Show detailed progress
        
    Returns:
        Intelligence report dictionary
    """
    print(f"\n🔍 Analyzing intelligence for {cve_id}")
    print("=" * 60)
    
    # Initialize aggregator
    aggregator = IntelligenceAggregator()
    
    # Collect and analyze intelligence
    if verbose:
        print("\n📡 Collecting intelligence from multiple sources...")
    
    intelligence_report = aggregator.aggregate_intelligence(cve_id)
    
    # Display results
    metadata = intelligence_report['metadata']
    print(f"\n📊 Intelligence Quality Score: {metadata['intelligence_quality_score']:.2%}")
    print(f"   Confidence Level: {metadata['confidence_level']}")
    
    # Executive summary
    print(f"\n📋 Executive Summary:")
    print(f"   {intelligence_report['executive_summary']}")
    
    # Key findings
    print(f"\n🔍 Intelligence Sources:")
    sources = intelligence_report['intelligence_sources']
    print(f"   Sources checked: {sources['sources_checked']}")
    print(f"   Sources with data: {sources['sources_with_data']}")
    print(f"   Primary sources: {', '.join(sources['primary_sources'])}")
    
    # Key features
    features = intelligence_report['key_features']
    print(f"\n📈 Feature Analysis:")
    print(f"   Total features extracted: {features['total_extracted']}")
    print(f"   Populated features: {features['populated_features']}")
    
    if features['critical_indicators']['positive']:
        print(f"\n   ✅ Positive Indicators:")
        for feature, importance in features['critical_indicators']['positive'][:3]:
            print(f"      • {feature}: {importance:.2f}")
    
    if features['critical_indicators']['negative']:
        print(f"\n   ⚠️  Negative Indicators:")
        for feature, importance in features['critical_indicators']['negative'][:3]:
            print(f"      • {feature}: {importance:.2f}")
    
    # Timeline
    timeline = intelligence_report['temporal_analysis']
    if timeline['timeline_events']:
        print(f"\n📅 Timeline:")
        for event in timeline['timeline_events'][:5]:
            print(f"   {event['date']}: {event['event']} ({event['source']})")
    
    if timeline['temporal_anomalies']:
        print(f"\n   ⚡ Anomalies detected:")
        for anomaly in timeline['temporal_anomalies']:
            print(f"      • {anomaly}")
    
    # Quality metrics
    if verbose:
        print(f"\n📊 Quality Metrics:")
        quality = intelligence_report['quality_metrics']
        for metric, value in quality.items():
            if metric != 'overall_quality':
                print(f"   {metric}: {value:.2%}")
    
    # Actionable intelligence
    actions = intelligence_report['actionable_intelligence']
    print(f"\n🎯 Actionable Intelligence:")
    print(f"   Priority Level: {actions['priority']}")
    
    if actions['recommended_actions']:
        print(f"   Recommended Actions:")
        for action in actions['recommended_actions']:
            print(f"      • {action}")
    
    if actions['monitoring_recommendations']:
        print(f"   Monitoring Recommendations:")
        for rec in actions['monitoring_recommendations']:
            print(f"      • {rec}")
    
    # Limitations
    limitations = intelligence_report['limitations']
    if limitations:
        print(f"\n⚠️  Intelligence Limitations:")
        for limitation in limitations:
            print(f"   • {limitation}")
    
    # Save report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = Path('intelligence_reports')
    output_dir.mkdir(exist_ok=True)
    report_file = output_dir / f'{cve_id}_intelligence_{timestamp}.json'
    
    with open(report_file, 'w') as f:
        json.dump(intelligence_report, f, indent=2, default=str)
    
    print(f"\n💾 Full intelligence report saved to: {report_file}")
    
    return intelligence_report


def batch_analysis(cve_list_file: str, output_csv: str = None):
    """
    Analyze multiple CVEs and generate summary statistics
    
    Args:
        cve_list_file: File containing CVE IDs (one per line)
        output_csv: Optional CSV output for summary
    """
    # Read CVE list
    with open(cve_list_file, 'r') as f:
        cve_ids = [line.strip() for line in f if line.strip()]
    
    print(f"\n📋 Analyzing {len(cve_ids)} CVEs for intelligence quality")
    
    results = []
    aggregator = IntelligenceAggregator()
    
    for i, cve_id in enumerate(cve_ids):
        print(f"\n[{i+1}/{len(cve_ids)}] Analyzing {cve_id}...")
        
        try:
            report = aggregator.aggregate_intelligence(cve_id)
            
            # Extract summary data
            result = {
                'cve_id': cve_id,
                'quality_score': report['metadata']['intelligence_quality_score'],
                'confidence_level': report['metadata']['confidence_level'],
                'sources_checked': report['intelligence_sources']['sources_checked'],
                'sources_with_data': report['intelligence_sources']['sources_with_data'],
                'features_extracted': report['key_features']['total_extracted'],
                'features_populated': report['key_features']['populated_features'],
                'priority': report['actionable_intelligence']['priority'],
                'limitations_count': len(report['limitations'])
            }
            
            # Add quality metrics
            for metric, value in report['quality_metrics'].items():
                result[f'metric_{metric}'] = value
            
            results.append(result)
            
        except Exception as e:
            logger.error(f"Error analyzing {cve_id}: {e}")
            results.append({
                'cve_id': cve_id,
                'quality_score': 0.0,
                'confidence_level': 'ERROR',
                'error': str(e)
            })
    
    # Generate summary statistics
    df = pd.DataFrame(results)
    
    print("\n" + "=" * 60)
    print("📊 INTELLIGENCE ANALYSIS SUMMARY")
    print("=" * 60)
    
    # Quality distribution
    print("\nQuality Score Distribution:")
    print(df['quality_score'].describe())
    
    print("\nConfidence Level Distribution:")
    print(df['confidence_level'].value_counts())
    
    print("\nPriority Distribution:")
    if 'priority' in df.columns:
        print(df['priority'].value_counts())
    
    # Average metrics
    metric_cols = [col for col in df.columns if col.startswith('metric_')]
    if metric_cols:
        print("\nAverage Quality Metrics:")
        for col in metric_cols:
            metric_name = col.replace('metric_', '')
            avg_value = df[col].mean()
            print(f"  {metric_name}: {avg_value:.2%}")
    
    # Save results
    if output_csv:
        df.to_csv(output_csv, index=False)
        print(f"\n💾 Results saved to: {output_csv}")
    
    return df


def main():
    parser = argparse.ArgumentParser(
        description='Analyze CVE intelligence using multi-source aggregation'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Single CVE analysis
    single_parser = subparsers.add_parser('analyze', help='Analyze single CVE')
    single_parser.add_argument('cve_id', help='CVE ID to analyze')
    single_parser.add_argument('-v', '--verbose', action='store_true', 
                              help='Show detailed analysis')
    
    # Batch analysis
    batch_parser = subparsers.add_parser('batch', help='Analyze multiple CVEs')
    batch_parser.add_argument('cve_list', help='File with CVE IDs (one per line)')
    batch_parser.add_argument('-o', '--output', help='Output CSV file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print("🎓 CVE Intelligence Analysis System")
    print("Focus: Information Quality & Coverage Metrics")
    
    if args.command == 'analyze':
        analyze_cve_intelligence(args.cve_id, args.verbose)
    
    elif args.command == 'batch':
        batch_analysis(args.cve_list, args.output)


if __name__ == "__main__":
    main()