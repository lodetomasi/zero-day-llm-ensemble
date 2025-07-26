"""
Multi-Agent System for Zero-Day Detection
"""
import time
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.agents.forensic import ForensicAnalyst
from src.agents.pattern import PatternDetector
from src.agents.temporal import TemporalAnalyst
from src.agents.attribution import AttributionExpert
from src.agents.meta import MetaAnalyst
from src.ensemble.thompson import ThompsonSampling
from src.ensemble.threshold_manager import ThresholdManager
from src.utils.logger import get_logger, experiment_logger
from src.utils.debug import debug_tracker
from config.settings import DEBUG_MODE, RATE_LIMIT_DELAY

logger = get_logger(__name__)


class MultiAgentSystem:
    """
    Ensemble of specialized LLM agents for zero-day detection
    """
    
    def __init__(self, use_thompson_sampling: bool = True, 
                 parallel_execution: bool = True):
        """
        Initialize multi-agent system
        
        Args:
            use_thompson_sampling: Whether to use Thompson Sampling for weights
            parallel_execution: Whether to run agents in parallel
        """
        # Initialize agents
        self.agents = {
            'ForensicAnalyst': ForensicAnalyst(),
            'PatternDetector': PatternDetector(),
            'TemporalAnalyst': TemporalAnalyst(),
            'AttributionExpert': AttributionExpert(),
            'MetaAnalyst': MetaAnalyst()
        }
        
        self.agent_names = list(self.agents.keys())
        self.n_agents = len(self.agents)
        
        # Thompson Sampling for weight optimization
        self.use_thompson_sampling = use_thompson_sampling
        if use_thompson_sampling:
            self.thompson_sampler = ThompsonSampling(self.n_agents)
            self.current_weights = self.thompson_sampler.sample_weights()
        else:
            # Equal weights
            self.current_weights = np.ones(self.n_agents) / self.n_agents
        
        # Initialize threshold manager
        self.threshold_manager = ThresholdManager()
        
        # Execution settings
        self.parallel_execution = parallel_execution
        if parallel_execution:
            self.executor = ThreadPoolExecutor(max_workers=self.n_agents)
        
        # Performance tracking
        self.predictions_made = 0
        self.total_time = 0.0
        
        logger.info(f"Initialized MultiAgentSystem with {self.n_agents} agents")
        logger.info(f"Thompson Sampling: {use_thompson_sampling}")
        logger.info(f"Parallel execution: {parallel_execution}")
    
    def analyze_vulnerability(self, cve_data: Dict[str, Any], 
                            verbose: bool = False) -> Dict[str, Any]:
        """
        Analyze vulnerability with all agents
        
        Args:
            cve_data: CVE data dictionary
            verbose: Whether to print detailed progress
            
        Returns:
            Dictionary with individual and ensemble predictions
        """
        start_time = time.time()
        self.predictions_made += 1
        
        cve_id = cve_data.get('cve_id', f'Unknown_{self.predictions_made}')
        
        if verbose or (DEBUG_MODE and self.predictions_made <= 5):
            logger.info(f"Analyzing {cve_id} with {self.n_agents} agents")
        
        # Get predictions from all agents
        if self.parallel_execution:
            agent_results = self._analyze_parallel(cve_data, verbose)
        else:
            agent_results = self._analyze_sequential(cve_data, verbose)
        
        # Calculate ensemble prediction
        ensemble_result = self.ensemble_prediction(agent_results, cve_data)
        
        # Log to experiment logger if available
        if experiment_logger:
            true_label = int(cve_data.get('is_zero_day', -1))
            if true_label != -1:
                experiment_logger.log_prediction(
                    cve_id,
                    true_label,
                    ensemble_result['prediction'],
                    {name: res['prediction'] for name, res in agent_results.items()},
                    ensemble_result['confidence']
                )
        
        # Track timing
        duration = time.time() - start_time
        self.total_time += duration
        
        result = {
            'cve_id': cve_id,
            'agent_predictions': agent_results,
            'ensemble': ensemble_result,
            'weights_used': self.current_weights.tolist(),
            'analysis_time': duration
        }
        
        if verbose:
            logger.info(f"Analysis complete in {duration:.2f}s")
            logger.info(f"Ensemble prediction: {ensemble_result['prediction']:.3f}")
        
        return result
    
    def calculate_ensemble_quality(self, predictions: np.ndarray, confidences: np.ndarray) -> Dict[str, float]:
        """
        Calculate quality metrics for ensemble predictions
        
        Args:
            predictions: Array of agent predictions
            confidences: Array of agent confidences
            
        Returns:
            Dictionary with quality metrics
        """
        # Disagreement among agents (high = uncertainty)
        disagreement = float(np.std(predictions))
        
        # Average confidence
        avg_confidence = float(np.mean(confidences))
        
        # Coherence - are all agents on same side of 0.5?
        binary_preds = predictions > 0.5
        coherence = len(set(binary_preds)) == 1
        
        # Confidence spread
        confidence_spread = float(np.std(confidences))
        
        # Decision margin - how far from 0.5 is the ensemble prediction
        ensemble_pred = np.mean(predictions)
        decision_margin = abs(ensemble_pred - 0.5)
        
        return {
            'disagreement': disagreement,
            'avg_confidence': avg_confidence,
            'coherence': coherence,
            'confidence_spread': confidence_spread,
            'decision_margin': decision_margin
        }
    
    def _analyze_parallel(self, cve_data: Dict[str, Any], 
                         verbose: bool) -> Dict[str, Any]:
        """Analyze with parallel execution"""
        futures = {}
        results = {}
        
        # Submit all tasks
        for agent_name, agent in self.agents.items():
            future = self.executor.submit(agent.analyze, cve_data)
            futures[future] = agent_name
        
        # Collect results as they complete
        for future in as_completed(futures):
            agent_name = futures[future]
            try:
                result = future.result(timeout=30)
                results[agent_name] = result
                
                if verbose:
                    pred = result.get('prediction', 0.5)
                    conf = result.get('confidence', 0.5)
                    logger.debug(f"{agent_name}: pred={pred:.3f}, conf={conf:.3f}")
                    
            except Exception as e:
                logger.error(f"{agent_name} failed: {e}")
                results[agent_name] = {
                    'prediction': 0.5,
                    'confidence': 0.1,
                    'reasoning': f"Error: {str(e)}",
                    'error': True
                }
        
        return results
    
    def _analyze_sequential(self, cve_data: Dict[str, Any], 
                           verbose: bool) -> Dict[str, Any]:
        """Analyze with sequential execution"""
        results = {}
        
        for i, (agent_name, agent) in enumerate(self.agents.items()):
            if verbose:
                logger.debug(f"[{i+1}/{self.n_agents}] {agent_name} analyzing...")
            
            try:
                result = agent.analyze(cve_data)
                results[agent_name] = result
                
                if verbose:
                    pred = result.get('prediction', 0.5)
                    conf = result.get('confidence', 0.5)
                    logger.debug(f"└─ Prediction: {pred:.3f}, Confidence: {conf:.3f}")
                
                # Rate limiting between agents
                if i < self.n_agents - 1:
                    time.sleep(RATE_LIMIT_DELAY)
                    
            except Exception as e:
                logger.error(f"{agent_name} failed: {e}")
                results[agent_name] = {
                    'prediction': 0.5,
                    'confidence': 0.1,
                    'reasoning': f"Error: {str(e)}",
                    'error': True
                }
        
        return results
    
    def ensemble_prediction(self, agent_results: Dict[str, Any], cve_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Combine agent predictions using current weights
        
        Args:
            agent_results: Dictionary of agent predictions
            
        Returns:
            Ensemble prediction and metadata
        """
        predictions = []
        confidences = []
        
        # Extract predictions in consistent order
        for i, agent_name in enumerate(self.agent_names):
            if agent_name in agent_results:
                result = agent_results[agent_name]
                predictions.append(result.get('prediction', 0.5))
                confidences.append(result.get('confidence', 0.5))
            else:
                predictions.append(0.5)
                confidences.append(0.1)
        
        predictions = np.array(predictions)
        confidences = np.array(confidences)
        
        # Weighted ensemble prediction
        ensemble_pred = np.average(predictions, weights=self.current_weights)
        
        # Confidence-weighted ensemble confidence
        conf_weights = confidences * self.current_weights
        conf_weights = conf_weights / conf_weights.sum() if conf_weights.sum() > 0 else self.current_weights
        ensemble_conf = np.average(confidences, weights=conf_weights)
        
        # Calculate agreement score
        binary_preds = (predictions > 0.5).astype(int)
        agreement = np.sum(binary_preds == binary_preds[0]) / len(binary_preds)
        
        # Uncertainty estimation
        pred_std = np.std(predictions)
        uncertainty = pred_std * (1 - ensemble_conf)
        
        # Calculate ensemble quality metrics
        quality_metrics = self.calculate_ensemble_quality(predictions, confidences)
        
        # Apply threshold manager adjustments
        if cve_data:
            source = cve_data.get('source', 'MANUAL')
            adjusted_pred = self.threshold_manager.adjust_prediction(
                ensemble_pred, source, ensemble_conf, agreement
            )
            
            # Get classification info
            classification = self.threshold_manager.classify(
                adjusted_pred, source, ensemble_conf
            )
            
            ensemble_pred = adjusted_pred
        
        return {
            'prediction': float(ensemble_pred),
            'confidence': float(ensemble_conf),
            'agreement': float(agreement),
            'uncertainty': float(uncertainty),
            'prediction_std': float(pred_std),
            'individual_predictions': predictions.tolist(),
            'individual_confidences': confidences.tolist(),
            'quality_metrics': quality_metrics
        }
    
    def update_weights(self, cve_id: str, true_label: int, 
                      agent_results: Dict[str, Any], 
                      ensemble_prediction: float) -> None:
        """
        Update agent weights based on performance
        
        Args:
            cve_id: CVE identifier
            true_label: True binary label
            agent_results: Agent predictions
            ensemble_prediction: Ensemble prediction
        """
        if not self.use_thompson_sampling:
            return
        
        # Create prediction dictionary with indices
        agent_predictions = {}
        for i, agent_name in enumerate(self.agent_names):
            if agent_name in agent_results:
                agent_predictions[i] = agent_results[agent_name]['prediction']
        
        # Update Thompson Sampling
        self.thompson_sampler.update(agent_predictions, true_label, ensemble_prediction)
        
        # Sample new weights
        self.current_weights = self.thompson_sampler.sample_weights()
        
        if DEBUG_MODE:
            logger.debug(f"Updated weights after {cve_id}: {self.current_weights}")
    
    def get_agent_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics for all agents"""
        stats = {
            'system_stats': {
                'total_predictions': self.predictions_made,
                'total_time': self.total_time,
                'avg_time_per_prediction': self.total_time / max(1, self.predictions_made)
            },
            'agent_stats': {},
            'weight_stats': {}
        }
        
        # Individual agent statistics
        for agent_name, agent in self.agents.items():
            stats['agent_stats'][agent_name] = agent.get_statistics()
        
        # Weight statistics
        if self.use_thompson_sampling:
            thompson_stats = self.thompson_sampler.get_agent_statistics()
            for i, agent_name in enumerate(self.agent_names):
                stats['weight_stats'][agent_name] = thompson_stats.get(f'agent_{i}', {})
        else:
            for agent_name in self.agent_names:
                stats['weight_stats'][agent_name] = {
                    'weight': 1.0 / self.n_agents,
                    'type': 'fixed'
                }
        
        return stats
    
    def test_connectivity(self) -> Dict[str, bool]:
        """Test connectivity to all agent models"""
        logger.info("Testing agent connectivity...")
        
        test_cve = {
            'cve_id': 'CVE-TEST-0001',
            'vendor': 'Test Vendor',
            'product': 'Test Product',
            'description': 'Test vulnerability for connectivity check',
            'source': 'TEST',
            'year': 2024,
            'is_zero_day': False
        }
        
        connectivity_results = {}
        
        for agent_name, agent in self.agents.items():
            try:
                logger.info(f"Testing {agent_name}...")
                result = agent.analyze(test_cve)
                
                # Check if we got valid response
                success = (
                    'prediction' in result and 
                    isinstance(result['prediction'], (int, float)) and
                    0 <= result['prediction'] <= 1
                )
                
                connectivity_results[agent_name] = success
                
                if success:
                    logger.info(f"✓ {agent_name}: Connected successfully")
                else:
                    logger.warning(f"✗ {agent_name}: Invalid response format")
                    
            except Exception as e:
                connectivity_results[agent_name] = False
                logger.error(f"✗ {agent_name}: Connection failed - {str(e)}")
            
            # Rate limiting
            time.sleep(RATE_LIMIT_DELAY)
        
        # Summary
        working_agents = sum(connectivity_results.values())
        total_agents = len(connectivity_results)
        
        logger.info(f"\nConnectivity Summary: {working_agents}/{total_agents} agents operational")
        
        return connectivity_results
    
    def shutdown(self):
        """Clean shutdown of the system"""
        if self.parallel_execution and hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)
            logger.info("Thread pool executor shut down")