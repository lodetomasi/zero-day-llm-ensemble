#!/usr/bin/env python3
"""
Comprehensive Test Suite for Zero-Day Detection System
Tests detection accuracy with verified ground truth
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

import json
import numpy as np
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)

from detect_zero_days import ZeroDayDetector
from src.evaluation.automated_evaluation import AutomatedEvaluator
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ComprehensiveTestSuite:
    """
    Comprehensive testing framework for zero-day detection system
    """
    
    def __init__(self):
        """Initialize test suite"""
        self.detector = ZeroDayDetector()
        self.evaluator = AutomatedEvaluator()
        self.results = []
        self.ground_truth = []
        self.predictions = []
        self.scores = []
        
    def prepare_test_dataset(self):
        """
        Prepare balanced test dataset with verified ground truth
        Based on multiple authoritative sources
        """
        # Confirmed zero-days (verified from multiple sources)
        confirmed_zero_days = [
            # 2024 Zero-days (from Google TAG report)
            ('CVE-2024-3400', 'Palo Alto PAN-OS - actively exploited before patch'),
            ('CVE-2024-23113', 'Fortinet FortiOS - exploited in wild'),
            ('CVE-2024-21762', 'Fortinet FortiOS - zero-day RCE'),
            ('CVE-2024-0012', 'Palo Alto PAN-OS - authentication bypass'),
            
            # 2023 High-profile zero-days
            ('CVE-2023-23397', 'Microsoft Outlook - Russian APT exploitation'),
            ('CVE-2023-20198', 'Cisco IOS XE - mass exploitation discovered'),
            ('CVE-2023-2868', 'Barracuda ESG - Chinese APT zero-day'),
            ('CVE-2023-22515', 'Atlassian Confluence - state actor zero-day'),
            ('CVE-2023-46805', 'Ivanti Connect Secure - pre-auth RCE'),
            ('CVE-2023-42793', 'JetBrains TeamCity - critical auth bypass'),
            
            # Additional verified zero-days
            ('CVE-2023-34362', 'MOVEit Transfer - Cl0p ransomware'),
            ('CVE-2023-27350', 'PaperCut - state actors exploitation'),
            ('CVE-2023-3519', 'Citrix NetScaler ADC - critical zero-day'),
            ('CVE-2023-4966', 'Citrix NetScaler - information disclosure'),
            ('CVE-2023-20109', 'Cisco IOS - zero-day vulnerability')
        ]
        
        # Confirmed NON zero-days (research/coordinated disclosure)
        confirmed_regular = [
            # Famous vulnerabilities discovered by research
            ('CVE-2021-44228', 'Log4Shell - discovered by Alibaba research'),
            ('CVE-2014-0160', 'Heartbleed - found by Google/Codenomicon'),
            ('CVE-2014-6271', 'Shellshock - researcher disclosure'),
            ('CVE-2017-5715', 'Spectre - academic research'),
            ('CVE-2018-11776', 'Apache Struts - security researcher'),
            
            # Recent high-severity but not zero-day
            ('CVE-2024-38063', 'Windows TCP/IP - patched before exploitation'),
            ('CVE-2024-21413', 'Microsoft Outlook - security update'),
            ('CVE-2024-4577', 'PHP CGI - responsible disclosure'),
            ('CVE-2024-6387', 'OpenSSH - regression fix'),
            ('CVE-2024-37032', 'Ollama - coordinated disclosure'),
            
            # Other verified non zero-days
            ('CVE-2024-1086', 'Linux Kernel - research disclosure'),
            ('CVE-2024-28995', 'SolarWinds - vendor patch'),
            ('CVE-2023-32233', 'Linux Kernel use-after-free'),
            ('CVE-2023-4911', 'GNU libc - Looney Tunables'),
            ('CVE-2023-38831', 'WinRAR - bug bounty finding')
        ]
        
        # Create test dataset
        test_data = []
        
        # Add zero-days
        for cve_id, description in confirmed_zero_days:
            test_data.append({
                'cve_id': cve_id,
                'is_zero_day': True,
                'description': description,
                'source': 'verified_intelligence'
            })
        
        # Add regular CVEs
        for cve_id, description in confirmed_regular:
            test_data.append({
                'cve_id': cve_id,
                'is_zero_day': False,
                'description': description,
                'source': 'verified_research'
            })
        
        # Shuffle for randomization
        import random
        random.seed(42)
        random.shuffle(test_data)
        
        logger.info(f"Prepared test dataset: {len(test_data)} CVEs")
        logger.info(f"Zero-days: {sum(1 for d in test_data if d['is_zero_day'])}")
        logger.info(f"Regular: {sum(1 for d in test_data if not d['is_zero_day'])}")
        
        return test_data
    
    def run_detection_test(self, test_data, verbose=False):
        """
        Run detection on test dataset
        """
        print("\n" + "="*60)
        print("🧪 RUNNING COMPREHENSIVE DETECTION TEST")
        print("="*60)
        print(f"\nTest dataset: {len(test_data)} CVEs")
        print(f"- Zero-days: {sum(1 for d in test_data if d['is_zero_day'])}")
        print(f"- Regular: {sum(1 for d in test_data if not d['is_zero_day'])}")
        print("\nStarting detection...\n")
        
        for i, test_case in enumerate(test_data):
            cve_id = test_case['cve_id']
            true_label = test_case['is_zero_day']
            
            print(f"[{i+1}/{len(test_data)}] Testing {cve_id}...", end='', flush=True)
            
            try:
                # Run detection
                result = self.detector.detect(cve_id, verbose=False)
                
                # Store results
                self.results.append(result)
                self.ground_truth.append(true_label)
                self.predictions.append(result['is_zero_day'])
                self.scores.append(result['detection_score'])
                
                # Quick result display
                if result['is_zero_day'] == true_label:
                    print(f" ✅ Correct ({result['confidence_level']} confidence)")
                else:
                    print(f" ❌ Wrong ({result['confidence_level']} confidence)")
                
                if verbose:
                    print(f"   Score: {result['detection_score']:.2%}")
                    print(f"   Key indicators: {', '.join(result['key_indicators'][:3])}")
                
            except Exception as e:
                logger.error(f"Error testing {cve_id}: {e}")
                print(f" ⚠️  Error: {e}")
                # Add null result
                self.results.append({'cve_id': cve_id, 'error': str(e)})
                self.ground_truth.append(true_label)
                self.predictions.append(False)  # Default to not zero-day on error
                self.scores.append(0.5)
        
        print("\n✅ Detection test completed!")
    
    def calculate_metrics(self):
        """
        Calculate comprehensive performance metrics
        """
        # Basic metrics
        accuracy = accuracy_score(self.ground_truth, self.predictions)
        precision = precision_score(self.ground_truth, self.predictions)
        recall = recall_score(self.ground_truth, self.predictions)
        f1 = f1_score(self.ground_truth, self.predictions)
        
        # Confusion matrix
        cm = confusion_matrix(self.ground_truth, self.predictions)
        tn, fp, fn, tp = cm.ravel()
        
        # ROC AUC
        fpr, tpr, thresholds = roc_curve(self.ground_truth, self.scores)
        roc_auc = auc(fpr, tpr)
        
        # Additional metrics
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # Confidence analysis
        high_conf = sum(1 for r in self.results if r.get('confidence_level') == 'HIGH')
        med_conf = sum(1 for r in self.results if r.get('confidence_level') == 'MEDIUM')
        low_conf = sum(1 for r in self.results if r.get('confidence_level') in ['LOW', 'VERY_LOW'])
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'specificity': specificity,
            'roc_auc': roc_auc,
            'confusion_matrix': {
                'true_positives': int(tp),
                'true_negatives': int(tn),
                'false_positives': int(fp),
                'false_negatives': int(fn)
            },
            'confidence_distribution': {
                'high': high_conf,
                'medium': med_conf,
                'low': low_conf
            },
            'error_rate': sum(1 for r in self.results if 'error' in r) / len(self.results)
        }
        
        return metrics
    
    def generate_visualizations(self, metrics, output_dir):
        """
        Generate comprehensive visualizations
        """
        plt.style.use('seaborn-v0_8-darkgrid')
        fig = plt.figure(figsize=(16, 10))
        
        # 1. Confusion Matrix
        ax1 = plt.subplot(2, 3, 1)
        cm = np.array([[metrics['confusion_matrix']['true_negatives'], 
                       metrics['confusion_matrix']['false_positives']],
                      [metrics['confusion_matrix']['false_negatives'], 
                       metrics['confusion_matrix']['true_positives']]])
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Regular', 'Zero-day'],
                   yticklabels=['Regular', 'Zero-day'])
        ax1.set_title('Confusion Matrix', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Predicted')
        ax1.set_ylabel('Actual')
        
        # 2. Metrics Bar Chart
        ax2 = plt.subplot(2, 3, 2)
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'Specificity']
        metric_values = [metrics['accuracy'], metrics['precision'], 
                        metrics['recall'], metrics['f1_score'], 
                        metrics['specificity']]
        
        bars = ax2.bar(metric_names, metric_values, color='skyblue', edgecolor='navy')
        ax2.set_ylim(0, 1.1)
        ax2.set_ylabel('Score')
        ax2.set_title('Performance Metrics', fontsize=14, fontweight='bold')
        
        # Add value labels
        for bar, value in zip(bars, metric_values):
            ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                    f'{value:.2%}', ha='center', va='bottom')
        
        # 3. ROC Curve
        ax3 = plt.subplot(2, 3, 3)
        fpr, tpr, _ = roc_curve(self.ground_truth, self.scores)
        ax3.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {metrics["roc_auc"]:.2f})')
        ax3.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        ax3.set_xlim([0.0, 1.0])
        ax3.set_ylim([0.0, 1.05])
        ax3.set_xlabel('False Positive Rate')
        ax3.set_ylabel('True Positive Rate')
        ax3.set_title('ROC Curve', fontsize=14, fontweight='bold')
        ax3.legend(loc="lower right")
        
        # 4. Score Distribution
        ax4 = plt.subplot(2, 3, 4)
        zero_day_scores = [s for s, t in zip(self.scores, self.ground_truth) if t]
        regular_scores = [s for s, t in zip(self.scores, self.ground_truth) if not t]
        
        ax4.hist(regular_scores, bins=20, alpha=0.5, label='Regular', color='blue')
        ax4.hist(zero_day_scores, bins=20, alpha=0.5, label='Zero-day', color='red')
        ax4.axvline(0.65, color='black', linestyle='--', label='Threshold')
        ax4.set_xlabel('Detection Score')
        ax4.set_ylabel('Count')
        ax4.set_title('Score Distribution by Class', fontsize=14, fontweight='bold')
        ax4.legend()
        
        # 5. Confidence Distribution
        ax5 = plt.subplot(2, 3, 5)
        conf_data = metrics['confidence_distribution']
        conf_labels = ['High', 'Medium', 'Low/Very Low']
        conf_values = [conf_data['high'], conf_data['medium'], conf_data['low']]
        
        ax5.pie(conf_values, labels=conf_labels, autopct='%1.1f%%', 
               colors=['green', 'yellow', 'red'])
        ax5.set_title('Confidence Distribution', fontsize=14, fontweight='bold')
        
        # 6. Error Analysis
        ax6 = plt.subplot(2, 3, 6)
        # Analyze false positives and false negatives
        fp_indices = [i for i, (p, t) in enumerate(zip(self.predictions, self.ground_truth)) 
                     if p and not t]
        fn_indices = [i for i, (p, t) in enumerate(zip(self.predictions, self.ground_truth)) 
                     if not p and t]
        
        error_types = ['False Positives', 'False Negatives', 'Correct']
        error_counts = [len(fp_indices), len(fn_indices), 
                       len(self.predictions) - len(fp_indices) - len(fn_indices)]
        
        ax6.bar(error_types, error_counts, color=['red', 'orange', 'green'])
        ax6.set_ylabel('Count')
        ax6.set_title('Error Analysis', fontsize=14, fontweight='bold')
        
        for i, (label, count) in enumerate(zip(error_types, error_counts)):
            ax6.text(i, count + 0.5, str(count), ha='center', va='bottom')
        
        plt.tight_layout()
        
        # Save visualization
        viz_file = output_dir / 'detection_test_results.png'
        plt.savefig(viz_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        return viz_file
    
    def analyze_errors(self):
        """
        Detailed error analysis
        """
        errors = {
            'false_positives': [],
            'false_negatives': [],
            'low_confidence_correct': [],
            'high_confidence_wrong': []
        }
        
        for i, result in enumerate(self.results):
            if 'error' in result:
                continue
                
            predicted = self.predictions[i]
            actual = self.ground_truth[i]
            confidence = result.get('confidence_level', 'UNKNOWN')
            
            # False positives
            if predicted and not actual:
                errors['false_positives'].append({
                    'cve_id': result['cve_id'],
                    'score': result['detection_score'],
                    'confidence': confidence,
                    'indicators': result.get('key_indicators', [])
                })
            
            # False negatives
            elif not predicted and actual:
                errors['false_negatives'].append({
                    'cve_id': result['cve_id'],
                    'score': result['detection_score'],
                    'confidence': confidence,
                    'indicators': result.get('key_indicators', [])
                })
            
            # Correct but low confidence
            elif predicted == actual and confidence in ['LOW', 'VERY_LOW']:
                errors['low_confidence_correct'].append({
                    'cve_id': result['cve_id'],
                    'score': result['detection_score']
                })
            
            # Wrong but high confidence
            elif predicted != actual and confidence == 'HIGH':
                errors['high_confidence_wrong'].append({
                    'cve_id': result['cve_id'],
                    'score': result['detection_score']
                })
        
        return errors
    
    def run_agent_evaluation(self):
        """
        Evaluate multi-agent collaboration
        """
        # Extract LLM results for evaluation
        llm_results = []
        for result in self.results:
            if 'llm_analysis' in result:
                llm_results.append(result['llm_analysis'])
        
        if llm_results:
            collab_metrics = self.evaluator.evaluate_agent_collaboration(llm_results)
            return collab_metrics
        
        return None
    
    def generate_comprehensive_report(self, test_data, metrics, errors, 
                                    collab_metrics, output_dir):
        """
        Generate comprehensive test report
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        report = {
            'test_metadata': {
                'timestamp': timestamp,
                'total_cves': len(test_data),
                'zero_days': sum(1 for d in test_data if d['is_zero_day']),
                'regular': sum(1 for d in test_data if not d['is_zero_day'])
            },
            'performance_metrics': metrics,
            'error_analysis': {
                'false_positives': len(errors['false_positives']),
                'false_negatives': len(errors['false_negatives']),
                'low_confidence_correct': len(errors['low_confidence_correct']),
                'high_confidence_wrong': len(errors['high_confidence_wrong']),
                'details': errors
            },
            'agent_collaboration': collab_metrics,
            'detailed_results': [
                {
                    'cve_id': result.get('cve_id'),
                    'actual': self.ground_truth[i],
                    'predicted': self.predictions[i],
                    'score': self.scores[i],
                    'confidence': result.get('confidence_level'),
                    'correct': self.predictions[i] == self.ground_truth[i]
                }
                for i, result in enumerate(self.results)
                if 'error' not in result
            ]
        }
        
        # Save report
        report_file = output_dir / f'comprehensive_test_report_{timestamp}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate summary text report
        summary_file = output_dir / f'test_summary_{timestamp}.txt'
        with open(summary_file, 'w') as f:
            f.write("ZERO-DAY DETECTION SYSTEM - COMPREHENSIVE TEST REPORT\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total CVEs Tested: {len(test_data)}\n")
            f.write(f"- Zero-days: {sum(1 for d in test_data if d['is_zero_day'])}\n")
            f.write(f"- Regular: {sum(1 for d in test_data if not d['is_zero_day'])}\n\n")
            
            f.write("PERFORMANCE METRICS\n")
            f.write("-"*30 + "\n")
            f.write(f"Accuracy:    {metrics['accuracy']:.2%}\n")
            f.write(f"Precision:   {metrics['precision']:.2%}\n")
            f.write(f"Recall:      {metrics['recall']:.2%}\n")
            f.write(f"F1-Score:    {metrics['f1_score']:.2%}\n")
            f.write(f"Specificity: {metrics['specificity']:.2%}\n")
            f.write(f"ROC AUC:     {metrics['roc_auc']:.3f}\n\n")
            
            f.write("CONFUSION MATRIX\n")
            f.write("-"*30 + "\n")
            f.write(f"True Positives:  {metrics['confusion_matrix']['true_positives']}\n")
            f.write(f"True Negatives:  {metrics['confusion_matrix']['true_negatives']}\n")
            f.write(f"False Positives: {metrics['confusion_matrix']['false_positives']}\n")
            f.write(f"False Negatives: {metrics['confusion_matrix']['false_negatives']}\n\n")
            
            f.write("ERROR ANALYSIS\n")
            f.write("-"*30 + "\n")
            f.write(f"False Positives: {len(errors['false_positives'])}\n")
            for fp in errors['false_positives'][:3]:
                f.write(f"  - {fp['cve_id']} (score: {fp['score']:.2%})\n")
            
            f.write(f"\nFalse Negatives: {len(errors['false_negatives'])}\n")
            for fn in errors['false_negatives'][:3]:
                f.write(f"  - {fn['cve_id']} (score: {fn['score']:.2%})\n")
            
            if collab_metrics:
                f.write("\nAGENT COLLABORATION\n")
                f.write("-"*30 + "\n")
                agreement = collab_metrics.get('agent_agreement', {})
                f.write(f"Overall Agreement: {agreement.get('overall_agreement', 0):.2%}\n")
                f.write(f"High Agreement Rate: {agreement.get('high_agreement_rate', 0):.2%}\n")
        
        return report_file, summary_file


def main():
    """
    Run comprehensive test suite
    """
    print("🧪 Zero-Day Detection System - Comprehensive Test Suite")
    print("="*60)
    
    # Setup
    output_dir = Path('test_results')
    output_dir.mkdir(exist_ok=True)
    
    # Initialize test suite
    test_suite = ComprehensiveTestSuite()
    
    # Prepare test data
    print("\n📋 Preparing test dataset...")
    test_data = test_suite.prepare_test_dataset()
    
    # Run detection test
    test_suite.run_detection_test(test_data, verbose=False)
    
    # Calculate metrics
    print("\n📊 Calculating performance metrics...")
    metrics = test_suite.calculate_metrics()
    
    # Error analysis
    print("🔍 Analyzing errors...")
    errors = test_suite.analyze_errors()
    
    # Agent evaluation
    print("🤖 Evaluating agent collaboration...")
    collab_metrics = test_suite.run_agent_evaluation()
    
    # Generate visualizations
    print("📈 Generating visualizations...")
    viz_file = test_suite.generate_visualizations(metrics, output_dir)
    
    # Generate report
    print("📝 Generating comprehensive report...")
    report_file, summary_file = test_suite.generate_comprehensive_report(
        test_data, metrics, errors, collab_metrics, output_dir
    )
    
    # Display results
    print("\n" + "="*60)
    print("📊 TEST RESULTS SUMMARY")
    print("="*60)
    print(f"\n✅ Accuracy:    {metrics['accuracy']:.2%}")
    print(f"✅ Precision:   {metrics['precision']:.2%}")
    print(f"✅ Recall:      {metrics['recall']:.2%}")
    print(f"✅ F1-Score:    {metrics['f1_score']:.2%}")
    print(f"✅ ROC AUC:     {metrics['roc_auc']:.3f}")
    
    print(f"\n📊 Confusion Matrix:")
    print(f"   TP: {metrics['confusion_matrix']['true_positives']} | "
          f"FP: {metrics['confusion_matrix']['false_positives']}")
    print(f"   FN: {metrics['confusion_matrix']['false_negatives']} | "
          f"TN: {metrics['confusion_matrix']['true_negatives']}")
    
    print(f"\n📄 Reports saved to:")
    print(f"   - {report_file}")
    print(f"   - {summary_file}")
    print(f"   - {viz_file}")
    
    print("\n✅ Comprehensive test completed successfully!")


if __name__ == "__main__":
    main()