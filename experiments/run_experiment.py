"""
Main experiment script for Zero-Day Detection System
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import time
from datetime import datetime
import numpy as np
import pandas as pd
from pathlib import Path
import json
from sklearn.model_selection import train_test_split

from config.settings import (
    RANDOM_SEED, TEST_SPLIT_RATIO, VALIDATION_SPLIT_RATIO,
    MAX_ZERO_DAYS, MAX_REGULAR_CVES, DEBUG_MODE
)
from src.data.collector import DataCollector
from src.data.preprocessor import DataPreprocessor
from src.ensemble.multi_agent import MultiAgentSystem
from src.evaluation.metrics import MetricsCalculator
from src.evaluation.statistical import StatisticalTester
from src.evaluation.visualization import Visualizer
from src.utils.logger import setup_experiment_logger, api_logger, get_logger
from src.utils.debug import debug_tracker

logger = get_logger(__name__)


class ZeroDayExperiment:
    """Main experiment runner"""
    
    def __init__(self, experiment_name: str, config: dict = None):
        self.experiment_name = experiment_name
        self.config = config or {}
        
        # Setup experiment logger
        self.exp_logger = setup_experiment_logger(experiment_name)
        
        # Initialize components
        self.data_collector = DataCollector()
        self.preprocessor = DataPreprocessor()
        self.metrics_calculator = MetricsCalculator()
        self.statistical_tester = StatisticalTester()
        self.visualizer = Visualizer()
        
        # Results storage
        self.results = {
            'experiment_name': experiment_name,
            'start_time': datetime.now().isoformat(),
            'config': self.config,
            'data_stats': {},
            'model_results': {},
            'statistical_tests': {},
            'figures': []
        }
    
    def run(self):
        """Run complete experiment"""
        logger.info(f"Starting experiment: {self.experiment_name}")
        logger.info("=" * 60)
        
        try:
            # Phase 1: Data Collection and Preprocessing
            logger.info("\nPHASE 1: Data Collection and Preprocessing")
            logger.info("-" * 40)
            dataset = self._collect_and_preprocess_data()
            
            # Phase 2: Train-Test Split
            logger.info("\nPHASE 2: Data Splitting")
            logger.info("-" * 40)
            train_data, test_data = self._split_data(dataset)
            
            # Phase 3: Multi-Agent System Evaluation
            logger.info("\nPHASE 3: Multi-Agent System Evaluation")
            logger.info("-" * 40)
            ma_results = self._evaluate_multi_agent(train_data, test_data)
            
            # Phase 4: Statistical Analysis
            logger.info("\nPHASE 4: Statistical Analysis")
            logger.info("-" * 40)
            self._perform_statistical_analysis(ma_results)
            
            # Phase 5: Visualization
            logger.info("\nPHASE 5: Creating Visualizations")
            logger.info("-" * 40)
            self._create_visualizations(ma_results)
            
            # Phase 6: Save Results
            logger.info("\nPHASE 6: Saving Results")
            logger.info("-" * 40)
            self._save_results()
            
            logger.info("\n" + "=" * 60)
            logger.info("EXPERIMENT COMPLETED SUCCESSFULLY!")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Experiment failed: {e}", exc_info=True)
            self.results['error'] = str(e)
            self._save_results()
            raise
    
    def _collect_and_preprocess_data(self):
        """Collect and preprocess data"""
        # Verify APIs
        api_status = self.data_collector.verify_apis()
        self.results['api_status'] = api_status
        
        # Collect data
        n_zero_days = self.config.get('n_zero_days', MAX_ZERO_DAYS)
        n_regular = self.config.get('n_regular_cves', MAX_REGULAR_CVES)
        
        dataset = self.data_collector.create_balanced_dataset(
            zero_day_count=n_zero_days,
            regular_count=n_regular,
            save_to_file=True
        )
        
        # Preprocess
        dataset = self.preprocessor.preprocess_dataset(dataset)
        
        # Check for data leakage
        leakage_report = self.preprocessor.check_data_leakage(dataset)
        if leakage_report['has_leakage']:
            logger.warning("Data leakage detected! Review the report.")
        
        # Store data statistics
        self.results['data_stats'] = {
            'total_samples': len(dataset),
            'zero_days': int(dataset['is_zero_day'].sum()),
            'regular_cves': int((~dataset['is_zero_day']).sum()),
            'preprocessing_report': self.preprocessor.get_preprocessing_report(),
            'leakage_report': leakage_report
        }
        
        logger.info(f"Dataset ready: {len(dataset)} samples")
        logger.info(f"Class distribution: {dataset['is_zero_day'].value_counts().to_dict()}")
        
        return dataset
    
    def _split_data(self, dataset):
        """Split data into train and test sets"""
        # Prepare for splitting
        X = dataset.drop('is_zero_day', axis=1)
        y = dataset['is_zero_day'].astype(int)
        
        # Stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=TEST_SPLIT_RATIO,
            stratify=y,
            random_state=RANDOM_SEED
        )
        
        # Recombine for processing
        train_data = X_train.copy()
        train_data['is_zero_day'] = y_train
        
        test_data = X_test.copy()
        test_data['is_zero_day'] = y_test
        
        logger.info(f"Train set: {len(train_data)} samples")
        logger.info(f"Test set: {len(test_data)} samples")
        logger.info(f"Train zero-day rate: {y_train.mean():.2%}")
        logger.info(f"Test zero-day rate: {y_test.mean():.2%}")
        
        return train_data, test_data
    
    def _evaluate_multi_agent(self, train_data, test_data):
        """Evaluate multi-agent system"""
        # Initialize system
        mas = MultiAgentSystem(
            use_thompson_sampling=True,
            parallel_execution=False  # Sequential for better debugging
        )
        
        # Test connectivity
        logger.info("\nTesting agent connectivity...")
        connectivity = mas.test_connectivity()
        self.results['agent_connectivity'] = connectivity
        
        if not all(connectivity.values()):
            logger.warning("Some agents are not operational!")
        
        # Convert to list of dicts for processing
        test_samples = test_data.to_dict('records')
        test_labels = test_data['is_zero_day'].values
        
        # Limit samples for testing if specified
        if self.config.get('max_test_samples'):
            max_samples = self.config['max_test_samples']
            test_samples = test_samples[:max_samples]
            test_labels = test_labels[:max_samples]
        
        # Evaluate each sample
        logger.info(f"\nEvaluating {len(test_samples)} test samples...")
        
        predictions = []
        probabilities = []
        all_results = []
        weights_history = [mas.current_weights.copy()]
        
        for i, (sample, true_label) in enumerate(zip(test_samples, test_labels)):
            # Progress indicator
            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i+1}/{len(test_samples)} ({(i+1)/len(test_samples)*100:.1f}%)")
            
            # Analyze
            result = mas.analyze_vulnerability(sample, verbose=(i < 5))
            all_results.append(result)
            
            # Extract prediction
            ensemble_pred = result['ensemble']['prediction']
            probabilities.append(ensemble_pred)
            predictions.append(int(ensemble_pred > 0.5))
            
            # Update weights if using Thompson Sampling
            if mas.use_thompson_sampling:
                mas.update_weights(
                    sample.get('cve_id', f'sample_{i}'),
                    int(true_label),
                    result['agent_predictions'],
                    ensemble_pred
                )
                weights_history.append(mas.current_weights.copy())
        
        # Calculate metrics
        predictions = np.array(predictions)
        probabilities = np.array(probabilities)
        
        metrics = self.metrics_calculator.calculate_metrics(
            test_labels, predictions, probabilities
        )
        
        # Per-class metrics
        per_class = self.metrics_calculator.calculate_per_class_metrics(
            test_labels, predictions
        )
        
        # Get curves data
        curves = self.metrics_calculator.get_curves(test_labels, probabilities)
        
        # Agent statistics
        agent_stats = mas.get_agent_statistics()
        
        # Package results
        results = {
            'predictions': predictions,
            'probabilities': probabilities,
            'true_labels': test_labels,
            'metrics': metrics,
            'per_class_metrics': per_class,
            'curves': curves,
            'agent_stats': agent_stats,
            'weights_history': weights_history,
            'all_results': all_results
        }
        
        # Log summary
        logger.info("\nMulti-Agent System Results:")
        logger.info(f"Accuracy: {metrics['accuracy']:.3f}")
        logger.info(f"Precision: {metrics['precision']:.3f}")
        logger.info(f"Recall: {metrics['recall']:.3f}")
        logger.info(f"F1-Score: {metrics['f1']:.3f}")
        if metrics.get('roc_auc') is not None:
            logger.info(f"ROC AUC: {metrics['roc_auc']:.3f}")
        
        # Store in results
        self.results['model_results']['multi_agent'] = results
        
        # Cleanup
        mas.shutdown()
        
        return results
    
    def _perform_statistical_analysis(self, ma_results):
        """Perform statistical analysis"""
        y_true = ma_results['true_labels']
        y_pred = ma_results['predictions']
        
        # Bootstrap confidence intervals
        logger.info("\nCalculating bootstrap confidence intervals...")
        
        for metric_name, metric_func in [
            ('accuracy', lambda y_t, y_p: np.mean(y_t == y_p)),
            ('precision', lambda y_t, y_p: np.sum((y_p == 1) & (y_t == 1)) / np.sum(y_p == 1) if np.sum(y_p == 1) > 0 else 0),
            ('recall', lambda y_t, y_p: np.sum((y_p == 1) & (y_t == 1)) / np.sum(y_t == 1) if np.sum(y_t == 1) > 0 else 0)
        ]:
            ci_result = self.statistical_tester.bootstrap_confidence_interval(
                y_true, y_pred, metric_func, n_bootstrap=1000
            )
            
            logger.info(f"{metric_name.capitalize()} CI: [{ci_result['lower_ci']:.3f}, {ci_result['upper_ci']:.3f}]")
            
            self.results['statistical_tests'][f'{metric_name}_ci'] = ci_result
        
        # Thompson Sampling convergence
        if 'weights_history' in ma_results:
            ts_convergence = self._analyze_thompson_convergence(ma_results['weights_history'])
            self.results['statistical_tests']['thompson_convergence'] = ts_convergence
    
    def _analyze_thompson_convergence(self, weights_history):
        """Analyze Thompson Sampling convergence"""
        weights_array = np.array(weights_history)
        
        # Calculate weight variance over time
        weight_variance = np.var(weights_array, axis=0)
        
        # Moving average of weights
        window_size = min(20, len(weights_history) // 5)
        if window_size > 1:
            moving_avg = np.convolve(weights_array[:, 0], 
                                    np.ones(window_size)/window_size, 
                                    mode='valid')
        else:
            moving_avg = weights_array[:, 0]
        
        return {
            'final_weights': weights_array[-1].tolist(),
            'weight_variance': weight_variance.tolist(),
            'converged': np.max(weight_variance) < 0.01,
            'iterations_to_convergence': len(weights_history)
        }
    
    def _create_visualizations(self, ma_results):
        """Create all visualizations"""
        logger.info("Creating visualizations...")
        
        # 1. ROC Curves
        curves_data = {
            'Multi-Agent Ensemble': ma_results['curves']['roc']
        }
        
        # Add individual agent ROCs if available
        if 'all_results' in ma_results and len(ma_results['all_results']) > 0:
            # Extract individual agent predictions
            agent_names = list(ma_results['all_results'][0]['agent_predictions'].keys())
            for agent_name in agent_names[:3]:  # Top 3 agents for clarity
                agent_probs = []
                for result in ma_results['all_results']:
                    agent_probs.append(result['agent_predictions'][agent_name]['prediction'])
                
                agent_probs = np.array(agent_probs)
                agent_curves = self.metrics_calculator.get_curves(
                    ma_results['true_labels'], agent_probs
                )
                curves_data[agent_name] = agent_curves['roc']
        
        fig_roc = self.visualizer.plot_roc_curves(curves_data)
        self.results['figures'].append('roc_curves')
        
        # 2. Confusion Matrix
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(ma_results['true_labels'], ma_results['predictions'])
        cm_data = {'Multi-Agent Ensemble': cm}
        
        fig_cm = self.visualizer.plot_confusion_matrices(cm_data)
        self.results['figures'].append('confusion_matrices')
        
        # 3. Weights Evolution
        if 'weights_history' in ma_results and len(ma_results['weights_history']) > 1:
            agent_names = ['ForensicAnalyst', 'PatternDetector', 'TemporalAnalyst', 
                          'AttributionExpert', 'MetaAnalyst']
            fig_weights = self.visualizer.plot_agent_weights_evolution(
                ma_results['weights_history'], agent_names
            )
            self.results['figures'].append('weights_evolution')
        
        # 4. Performance Comparison
        metrics_data = {
            'Multi-Agent': ma_results['metrics']
        }
        
        fig_perf = self.visualizer.plot_performance_comparison(metrics_data)
        self.results['figures'].append('performance_comparison')
        
        logger.info(f"Created {len(self.results['figures'])} visualizations")
    
    def _save_results(self):
        """Save all results"""
        self.results['end_time'] = datetime.now().isoformat()
        
        # Save experiment log
        self.exp_logger.log_metrics(self.results.get('model_results', {}).get('multi_agent', {}).get('metrics', {}))
        results_file = self.exp_logger.save_results()
        
        # Save debug report if in debug mode
        if DEBUG_MODE:
            debug_report = debug_tracker.generate_debug_report()
            debug_file = Path(results_file).parent / 'debug_report.txt'
            with open(debug_file, 'w') as f:
                f.write(debug_report)
            logger.info(f"Debug report saved to: {debug_file}")
        
        # Save main results
        main_results_file = Path(results_file).parent / 'experiment_results.json'
        with open(main_results_file, 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            def convert_numpy(obj):
                if isinstance(obj, np.ndarray):
                    return obj.tolist()
                elif isinstance(obj, np.integer):
                    return int(obj)
                elif isinstance(obj, np.floating):
                    return float(obj)
                elif isinstance(obj, dict):
                    return {k: convert_numpy(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_numpy(v) for v in obj]
                else:
                    return obj
            
            json.dump(convert_numpy(self.results), f, indent=2)
        
        logger.info(f"Results saved to: {main_results_file}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Run Zero-Day Detection Experiment')
    parser.add_argument('--name', type=str, default=f'experiment_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                       help='Experiment name')
    parser.add_argument('--max-samples', type=int, default=50,
                       help='Maximum test samples to evaluate')
    parser.add_argument('--zero-days', type=int, default=50,
                       help='Number of zero-days to collect')
    parser.add_argument('--regular-cves', type=int, default=50,
                       help='Number of regular CVEs to collect')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Configuration
    config = {
        'max_test_samples': args.max_samples,
        'n_zero_days': args.zero_days,
        'n_regular_cves': args.regular_cves,
        'debug': args.debug
    }
    
    # Run experiment
    experiment = ZeroDayExperiment(args.name, config)
    experiment.run()


if __name__ == '__main__':
    main()