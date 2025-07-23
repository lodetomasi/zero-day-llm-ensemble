"""
Thompson Sampling for dynamic weight optimization
"""
import numpy as np
from typing import List, Dict, Any, Tuple
from collections import defaultdict

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ThompsonSampling:
    """
    Thompson Sampling for online learning of agent weights
    Uses Beta distribution for binary outcomes
    """
    
    def __init__(self, n_agents: int, prior_alpha: float = 1.0, prior_beta: float = 1.0):
        """
        Initialize Thompson Sampling
        
        Args:
            n_agents: Number of agents
            prior_alpha: Prior success parameter (default=1 for uniform prior)
            prior_beta: Prior failure parameter (default=1 for uniform prior)
        """
        self.n_agents = n_agents
        
        # Beta distribution parameters for each agent
        self.alpha = np.ones(n_agents) * prior_alpha  # Success counts
        self.beta = np.ones(n_agents) * prior_beta    # Failure counts
        
        # History tracking
        self.history = []
        self.agent_performance = defaultdict(lambda: {'correct': 0, 'total': 0})
        
        # Exploration parameters
        self.exploration_bonus = 0.1
        self.min_observations = 5
        
        logger.info(f"Initialized Thompson Sampling with {n_agents} agents")
    
    def sample_weights(self, exploration_mode: bool = True) -> np.ndarray:
        """
        Sample weights from Beta distributions
        
        Args:
            exploration_mode: Whether to add exploration bonus
            
        Returns:
            Normalized weight vector
        """
        # Sample from Beta distributions
        samples = np.array([
            np.random.beta(self.alpha[i], self.beta[i]) 
            for i in range(self.n_agents)
        ])
        
        # Add exploration bonus for under-sampled agents
        if exploration_mode:
            total_observations = self.alpha + self.beta - 2  # Subtract prior
            for i in range(self.n_agents):
                if total_observations[i] < self.min_observations:
                    samples[i] += self.exploration_bonus
        
        # Normalize to sum to 1
        weights = samples / samples.sum()
        
        return weights
    
    def get_expected_weights(self) -> np.ndarray:
        """
        Get expected weights (mean of Beta distributions)
        
        Returns:
            Expected weight vector
        """
        expected_values = self.alpha / (self.alpha + self.beta)
        return expected_values / expected_values.sum()
    
    def update(self, agent_predictions: Dict[str, float], 
               true_label: int, ensemble_prediction: float) -> None:
        """
        Update agent parameters based on performance
        
        Args:
            agent_predictions: Dictionary mapping agent index to prediction
            true_label: True binary label (0 or 1)
            ensemble_prediction: Ensemble's prediction
        """
        # Update each agent based on individual performance
        for agent_idx, prediction in agent_predictions.items():
            # Convert prediction to binary
            binary_pred = int(prediction > 0.5)
            correct = binary_pred == true_label
            
            # Update Beta parameters
            if correct:
                self.alpha[agent_idx] += 1
            else:
                self.beta[agent_idx] += 1
            
            # Track performance
            self.agent_performance[agent_idx]['total'] += 1
            if correct:
                self.agent_performance[agent_idx]['correct'] += 1
        
        # Record history
        self.history.append({
            'true_label': true_label,
            'ensemble_prediction': ensemble_prediction,
            'agent_predictions': agent_predictions,
            'alpha': self.alpha.copy(),
            'beta': self.beta.copy(),
            'timestamp': len(self.history)
        })
    
    def update_with_confidence(self, agent_idx: int, prediction: float, 
                              confidence: float, true_label: int) -> None:
        """
        Update with confidence-weighted reward
        
        Args:
            agent_idx: Agent index
            prediction: Agent's prediction
            confidence: Agent's confidence
            true_label: True label
        """
        binary_pred = int(prediction > 0.5)
        correct = binary_pred == true_label
        
        # Weight update by confidence
        if correct:
            # Reward more for correct high-confidence predictions
            self.alpha[agent_idx] += confidence
        else:
            # Penalize more for incorrect high-confidence predictions
            self.beta[agent_idx] += confidence
    
    def get_agent_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics for each agent"""
        stats = {}
        
        for i in range(self.n_agents):
            total_obs = self.alpha[i] + self.beta[i] - 2  # Subtract prior
            
            if total_obs > 0:
                # Calculate statistics
                mean = self.alpha[i] / (self.alpha[i] + self.beta[i])
                variance = (self.alpha[i] * self.beta[i]) / \
                          ((self.alpha[i] + self.beta[i])**2 * (self.alpha[i] + self.beta[i] + 1))
                
                # Confidence interval (95%)
                std_dev = np.sqrt(variance)
                ci_lower = max(0, mean - 1.96 * std_dev)
                ci_upper = min(1, mean + 1.96 * std_dev)
                
                # Performance metrics
                perf = self.agent_performance[i]
                accuracy = perf['correct'] / perf['total'] if perf['total'] > 0 else 0
                
                stats[f'agent_{i}'] = {
                    'expected_weight': mean,
                    'variance': variance,
                    'confidence_interval': (ci_lower, ci_upper),
                    'total_observations': int(total_obs),
                    'accuracy': accuracy,
                    'alpha': self.alpha[i],
                    'beta': self.beta[i]
                }
            else:
                stats[f'agent_{i}'] = {
                    'expected_weight': 0.5,
                    'variance': 0.0,
                    'confidence_interval': (0.0, 1.0),
                    'total_observations': 0,
                    'accuracy': 0.0,
                    'alpha': self.alpha[i],
                    'beta': self.beta[i]
                }
        
        return stats
    
    def recommend_exploration(self) -> List[int]:
        """
        Recommend which agents need more exploration
        
        Returns:
            List of agent indices that need more data
        """
        under_explored = []
        
        total_observations = self.alpha + self.beta - 2
        min_obs = np.min(total_observations)
        median_obs = np.median(total_observations)
        
        for i in range(self.n_agents):
            if total_observations[i] < max(self.min_observations, median_obs * 0.5):
                under_explored.append(i)
        
        return under_explored
    
    def convergence_diagnostic(self) -> Dict[str, Any]:
        """
        Diagnose convergence of the sampling process
        
        Returns:
            Convergence metrics
        """
        if len(self.history) < 10:
            return {'converged': False, 'reason': 'Insufficient data'}
        
        # Check weight stability over recent history
        recent_weights = []
        for i in range(max(0, len(self.history) - 20), len(self.history)):
            weights = self.get_expected_weights()
            recent_weights.append(weights)
        
        recent_weights = np.array(recent_weights)
        weight_variance = np.var(recent_weights, axis=0)
        max_variance = np.max(weight_variance)
        
        # Check if weights have stabilized
        converged = max_variance < 0.01
        
        return {
            'converged': converged,
            'max_weight_variance': max_variance,
            'iterations': len(self.history),
            'weight_variances': weight_variance.tolist()
        }