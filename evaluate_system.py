#!/usr/bin/env python3
"""
Automated system evaluation focusing on multi-agent collaboration
No human evaluation needed - demonstrates agent synergy and performance
"""
import argparse
import json
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import numpy as np

import sys
sys.path.append(str(Path(__file__).parent))

from src.evaluation.automated_evaluation import AutomatedEvaluator
from src.intelligence.aggregator import IntelligenceAggregator
from src.utils.logger import get_logger

logger = get_logger(__name__)


def visualize_agent_collaboration(report: dict, output_dir: Path):
    """Create visualizations of agent collaboration metrics"""
    
    # Set style
    plt.style.use('seaborn-v0_8-darkgrid')
    fig = plt.figure(figsize=(16, 12))
    
    # 1. Agent Agreement Heatmap
    ax1 = plt.subplot(2, 3, 1)
    agreement_data = report['collaboration_metrics']['agent_agreement']['pairwise_agreement']
    
    # Create matrix for heatmap
    agents = ['Forensic', 'Pattern', 'Temporal', 'Attribution', 'Meta']
    matrix = np.ones((5, 5))
    
    agent_map = {
        'ForensicAnalyst': 0, 'PatternDetector': 1, 
        'TemporalAnalyst': 2, 'AttributionExpert': 3, 'MetaAnalyst': 4
    }
    
    for pair, value in agreement_data.items():
        parts = pair.split('_vs_')
        if len(parts) == 2 and parts[0] in agent_map and parts[1] in agent_map:
            i, j = agent_map[parts[0]], agent_map[parts[1]]
            matrix[i, j] = value
            matrix[j, i] = value
    
    sns.heatmap(matrix, annot=True, fmt='.2f', cmap='RdYlGn', 
                xticklabels=agents, yticklabels=agents, vmin=0, vmax=1)
    ax1.set_title('Agent Pairwise Agreement', fontsize=14, fontweight='bold')
    
    # 2. Agent Specialization Scores
    ax2 = plt.subplot(2, 3, 2)
    specialization = report['collaboration_metrics']['agent_specialization']
    
    agents_short = []
    spec_scores = []
    for agent, data in specialization.items():
        agents_short.append(agent.replace('Analyst', '').replace('Detector', ''))
        spec_scores.append(data['specialization_score'])
    
    bars = ax2.bar(agents_short, spec_scores, color='skyblue', edgecolor='navy')
    ax2.set_ylabel('Specialization Score', fontweight='bold')
    ax2.set_title('Agent Specialization', fontsize=14, fontweight='bold')
    ax2.set_ylim(0, max(spec_scores) * 1.2 if spec_scores else 1)
    
    # Add value labels on bars
    for bar, score in zip(bars, spec_scores):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{score:.2f}', ha='center', va='bottom')
    
    # 3. Confidence Calibration
    ax3 = plt.subplot(2, 3, 3)
    calibration = report['collaboration_metrics']['confidence_calibration']
    
    agents_calib = []
    calib_errors = []
    for agent, data in calibration.items():
        if agent != 'ensemble':
            agents_calib.append(agent.replace('Analyst', '').replace('Detector', ''))
            calib_errors.append(data['calibration_error'])
    
    bars = ax3.bar(agents_calib, calib_errors, color='coral', edgecolor='darkred')
    ax3.set_ylabel('Calibration Error', fontweight='bold')
    ax3.set_title('Agent Confidence Calibration', fontsize=14, fontweight='bold')
    ax3.set_ylim(0, max(calib_errors) * 1.2 if calib_errors else 1)
    
    # 4. Agent Contributions
    ax4 = plt.subplot(2, 3, 4)
    contributions = report['collaboration_metrics']['agent_contribution']
    
    agents_contrib = []
    avg_contributions = []
    unique_insights = []
    
    for agent, data in contributions.items():
        agents_contrib.append(agent.replace('Analyst', '').replace('Detector', ''))
        avg_contributions.append(data['avg_contribution'])
        unique_insights.append(data['unique_insight_rate'])
    
    x = np.arange(len(agents_contrib))
    width = 0.35
    
    bars1 = ax4.bar(x - width/2, avg_contributions, width, label='Avg Contribution', color='lightgreen')
    bars2 = ax4.bar(x + width/2, unique_insights, width, label='Unique Insights', color='lightcoral')
    
    ax4.set_ylabel('Score', fontweight='bold')
    ax4.set_title('Agent Contributions', fontsize=14, fontweight='bold')
    ax4.set_xticks(x)
    ax4.set_xticklabels(agents_contrib, rotation=45)
    ax4.legend()
    
    # 5. System Quality Distribution
    ax5 = plt.subplot(2, 3, 5)
    quality_score = report['system_performance']['avg_quality_score']
    quality_std = report['system_performance']['quality_score_std']
    
    # Create synthetic distribution for visualization
    quality_samples = np.random.normal(quality_score, quality_std, 1000)
    quality_samples = np.clip(quality_samples, 0, 1)
    
    ax5.hist(quality_samples, bins=30, color='mediumpurple', edgecolor='indigo', alpha=0.7)
    ax5.axvline(quality_score, color='red', linestyle='--', linewidth=2, label=f'Mean: {quality_score:.2f}')
    ax5.set_xlabel('Intelligence Quality Score', fontweight='bold')
    ax5.set_ylabel('Frequency', fontweight='bold')
    ax5.set_title('Intelligence Quality Distribution', fontsize=14, fontweight='bold')
    ax5.legend()
    
    # 6. Agent Performance Grades
    ax6 = plt.subplot(2, 3, 6)
    summary = report['agent_performance_summary']
    
    agents_grade = []
    grades = []
    grade_colors = {'A': 'darkgreen', 'B': 'green', 'C': 'orange', 'D': 'red'}
    colors = []
    
    for agent, data in summary.items():
        agents_grade.append(agent.replace('Analyst', '').replace('Detector', ''))
        grade = data['performance_grade']
        grades.append(grade)
        colors.append(grade_colors.get(grade, 'gray'))
    
    y_pos = np.arange(len(agents_grade))
    ax6.barh(y_pos, [1]*len(agents_grade), color=colors, edgecolor='black')
    
    for i, (agent, grade) in enumerate(zip(agents_grade, grades)):
        ax6.text(0.5, i, grade, ha='center', va='center', 
                fontsize=16, fontweight='bold', color='white')
    
    ax6.set_yticks(y_pos)
    ax6.set_yticklabels(agents_grade)
    ax6.set_xlim(0, 1)
    ax6.set_xticks([])
    ax6.set_title('Agent Performance Grades', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    
    # Save figure
    output_file = output_dir / 'agent_collaboration_analysis.png'
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Visualization saved to {output_file}")
    return output_file


def run_evaluation(cve_list: list, output_dir: Path, sample_size: int = None):
    """Run automated evaluation on CVE list"""
    
    logger.info(f"Starting evaluation of {len(cve_list)} CVEs")
    
    # Initialize components
    aggregator = IntelligenceAggregator()
    evaluator = AutomatedEvaluator()
    
    # Sample if needed
    if sample_size and sample_size < len(cve_list):
        import random
        cve_list = random.sample(cve_list, sample_size)
        logger.info(f"Sampled {sample_size} CVEs for evaluation")
    
    # Collect intelligence reports
    intelligence_results = []
    
    for i, cve_id in enumerate(cve_list):
        logger.info(f"[{i+1}/{len(cve_list)}] Analyzing {cve_id}")
        
        try:
            report = aggregator.aggregate_intelligence(cve_id)
            intelligence_results.append(report)
        except Exception as e:
            logger.error(f"Error analyzing {cve_id}: {e}")
    
    # Generate evaluation report
    logger.info("Generating evaluation report...")
    evaluation_report = evaluator.generate_evaluation_report(intelligence_results)
    
    # Save evaluation report
    report_file = output_dir / f'evaluation_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_file, 'w') as f:
        json.dump(evaluation_report, f, indent=2, default=str)
    
    logger.info(f"Evaluation report saved to {report_file}")
    
    # Generate visualizations
    viz_file = visualize_agent_collaboration(evaluation_report, output_dir)
    
    # Print summary
    print("\n" + "="*60)
    print("EVALUATION SUMMARY")
    print("="*60)
    
    print(f"\nCVEs Evaluated: {len(intelligence_results)}")
    print(f"Average Intelligence Quality: {evaluation_report['system_performance']['avg_quality_score']:.2%}")
    
    print("\nAgent Collaboration Metrics:")
    print(f"  Overall Agreement: {evaluation_report['collaboration_metrics']['agent_agreement']['overall_agreement']:.2%}")
    print(f"  Ensemble Stability: {evaluation_report['collaboration_metrics']['ensemble_stability']['stability_score']:.2%}")
    
    print("\nKey Findings:")
    for finding in evaluation_report['key_findings'][:5]:
        print(f"  • {finding}")
    
    print("\nAgent Performance Summary:")
    for agent, data in evaluation_report['agent_performance_summary'].items():
        print(f"  {agent}: Grade {data['performance_grade']} "
              f"(Specialization: {data['specialization_score']:.2f}, "
              f"Insights: {data['unique_insights']})")
    
    print("\nRecommendations:")
    for rec in evaluation_report['recommendations']:
        print(f"  • {rec}")
    
    print(f"\n📊 Full report: {report_file}")
    print(f"📈 Visualizations: {viz_file}")
    
    return evaluation_report


def main():
    parser = argparse.ArgumentParser(
        description='Evaluate multi-agent intelligence system performance'
    )
    parser.add_argument('--cve-file', type=str, help='File containing CVE IDs')
    parser.add_argument('--sample-cves', type=int, default=20, 
                       help='Number of CVEs to sample for evaluation')
    parser.add_argument('--output-dir', type=str, default='evaluation_results',
                       help='Output directory for results')
    parser.add_argument('--use-test-set', action='store_true',
                       help='Use predefined test set of CVEs')
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Get CVE list
    if args.use_test_set:
        # Predefined diverse test set
        cve_list = [
            # Confirmed zero-days from research
            'CVE-2023-23397',  # Microsoft Outlook
            'CVE-2023-20198',  # Cisco IOS XE
            'CVE-2024-3400',   # Palo Alto PAN-OS
            'CVE-2023-2868',   # Barracuda ESG
            'CVE-2023-22515',  # Atlassian Confluence
            
            # High-profile vulnerabilities (not zero-days)
            'CVE-2021-44228',  # Log4Shell
            'CVE-2014-0160',   # Heartbleed
            'CVE-2017-5715',   # Spectre
            'CVE-2024-21413',  # Microsoft Outlook
            'CVE-2024-38063',  # Windows TCP/IP
            
            # Recent CVEs for diversity
            'CVE-2024-23113',  # Fortinet FortiOS
            'CVE-2024-27198',  # JetBrains TeamCity
            'CVE-2024-4577',   # PHP CGI
            'CVE-2024-37032',  # Ollama
            'CVE-2024-6387',   # OpenSSH
            
            # Mix of severities and vendors
            'CVE-2023-46805',  # Ivanti Connect Secure
            'CVE-2024-1086',   # Linux Kernel
            'CVE-2024-21762',  # Fortinet FortiOS
            'CVE-2023-42793',  # JetBrains TeamCity
            'CVE-2024-28995'   # SolarWinds
        ]
    elif args.cve_file:
        with open(args.cve_file, 'r') as f:
            cve_list = [line.strip() for line in f if line.strip()]
    else:
        # Generate sample from CISA KEV or other source
        print("No CVE source specified. Using test set.")
        parser.print_help()
        return
    
    # Run evaluation
    print("🔬 Multi-Agent System Evaluation")
    print("="*60)
    print(f"Evaluating agent collaboration and intelligence quality")
    print(f"CVEs to analyze: {min(len(cve_list), args.sample_cves)}")
    print(f"Output directory: {output_dir}")
    print("="*60)
    
    evaluation_report = run_evaluation(cve_list, output_dir, args.sample_cves)


if __name__ == "__main__":
    main()