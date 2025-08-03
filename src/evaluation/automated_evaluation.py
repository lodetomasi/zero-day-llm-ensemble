"""
Automated evaluation system for multi-agent intelligence framework
No human evaluation needed - uses objective metrics and agent agreement
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import cohen_kappa_score
import logging

logger = logging.getLogger(__name__)


class AutomatedEvaluator:
    """
    Evaluate multi-agent system performance using objective metrics
    Focus on agent collaboration quality, not human validation
    """
    
    def __init__(self):
        """Initialize automated evaluator"""
        self.agent_names = [
            'ForensicAnalyst', 
            'PatternDetector', 
            'TemporalAnalyst',
            'AttributionExpert', 
            'MetaAnalyst'
        ]
        
    def evaluate_agent_collaboration(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate how well agents collaborate and agree
        
        Args:
            results: List of analysis results
            
        Returns:
            Collaboration metrics
        """
        collaboration_metrics = {
            'agent_agreement': self._calculate_agent_agreement(results),
            'agent_specialization': self._measure_agent_specialization(results),
            'ensemble_stability': self._calculate_ensemble_stability(results),
            'confidence_calibration': self._evaluate_confidence_calibration(results),
            'agent_contribution': self._analyze_agent_contributions(results)
        }
        
        return collaboration_metrics
    
    def _calculate_agent_agreement(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate agreement between agents using various metrics"""
        agreement_scores = []
        pairwise_agreements = {f"{a1}_vs_{a2}": [] 
                              for i, a1 in enumerate(self.agent_names) 
                              for a2 in self.agent_names[i+1:]}
        
        for result in results:
            agent_preds = result.get('agent_predictions', {})
            
            # Overall agreement (standard deviation)
            predictions = [agent_preds.get(agent, {}).get('prediction', 0.5) 
                          for agent in self.agent_names]
            agreement_scores.append(1 - np.std(predictions))
            
            # Pairwise agreement
            for i, agent1 in enumerate(self.agent_names):
                for agent2 in self.agent_names[i+1:]:
                    pred1 = agent_preds.get(agent1, {}).get('prediction', 0.5)
                    pred2 = agent_preds.get(agent2, {}).get('prediction', 0.5)
                    # Agreement as 1 - |difference|
                    pair_agreement = 1 - abs(pred1 - pred2)
                    pairwise_agreements[f"{agent1}_vs_{agent2}"].append(pair_agreement)
        
        return {
            'overall_agreement': np.mean(agreement_scores),
            'agreement_std': np.std(agreement_scores),
            'pairwise_agreement': {k: np.mean(v) for k, v in pairwise_agreements.items()},
            'high_agreement_rate': sum(s > 0.7 for s in agreement_scores) / len(agreement_scores)
        }
    
    def _measure_agent_specialization(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Measure how specialized each agent is in their domain"""
        agent_patterns = {agent: {
            'high_confidence_correct': 0,
            'high_confidence_total': 0,
            'unique_insights': 0,
            'deviation_from_ensemble': []
        } for agent in self.agent_names}
        
        for result in results:
            agent_preds = result.get('agent_predictions', {})
            ensemble_pred = result.get('ensemble', {}).get('prediction', 0.5)
            
            for agent in self.agent_names:
                agent_data = agent_preds.get(agent, {})
                pred = agent_data.get('prediction', 0.5)
                conf = agent_data.get('confidence', 0.5)
                
                # Track high confidence predictions
                if conf > 0.7:
                    agent_patterns[agent]['high_confidence_total'] += 1
                    # Check if agent was correct when ensemble was wrong
                    if abs(pred - ensemble_pred) > 0.3:
                        agent_patterns[agent]['unique_insights'] += 1
                
                # Deviation from ensemble
                deviation = abs(pred - ensemble_pred)
                agent_patterns[agent]['deviation_from_ensemble'].append(deviation)
        
        # Calculate specialization scores
        specialization = {}
        for agent, patterns in agent_patterns.items():
            total = patterns['high_confidence_total']
            unique = patterns['unique_insights']
            
            specialization[agent] = {
                'specialization_score': unique / max(1, total),
                'avg_deviation': np.mean(patterns['deviation_from_ensemble']),
                'high_confidence_rate': total / len(results),
                'unique_insight_rate': unique / len(results)
            }
        
        return specialization
    
    def _calculate_ensemble_stability(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Measure ensemble stability across different CVE types"""
        stability_metrics = {
            'prediction_variance': [],
            'confidence_variance': [],
            'agent_dropout_impact': []
        }
        
        for result in results:
            ensemble = result.get('ensemble', {})
            
            # Prediction variance
            if 'individual_predictions' in ensemble:
                pred_var = np.var(ensemble['individual_predictions'])
                stability_metrics['prediction_variance'].append(pred_var)
            
            # Confidence variance
            if 'individual_confidences' in ensemble:
                conf_var = np.var(ensemble['individual_confidences'])
                stability_metrics['confidence_variance'].append(conf_var)
            
            # Simulate agent dropout impact
            if 'individual_predictions' in ensemble:
                all_preds = ensemble['individual_predictions']
                full_ensemble = np.mean(all_preds)
                
                # Calculate ensemble without each agent
                for i in range(len(all_preds)):
                    subset_preds = all_preds[:i] + all_preds[i+1:]
                    subset_ensemble = np.mean(subset_preds)
                    impact = abs(full_ensemble - subset_ensemble)
                    stability_metrics['agent_dropout_impact'].append(impact)
        
        return {
            'avg_prediction_variance': np.mean(stability_metrics['prediction_variance']),
            'avg_confidence_variance': np.mean(stability_metrics['confidence_variance']),
            'avg_dropout_impact': np.mean(stability_metrics['agent_dropout_impact']),
            'max_dropout_impact': np.max(stability_metrics['agent_dropout_impact']) if stability_metrics['agent_dropout_impact'] else 0,
            'stability_score': 1 - np.mean(stability_metrics['prediction_variance'])  # Higher is more stable
        }
    
    def _evaluate_confidence_calibration(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Evaluate if agent confidence matches actual performance"""
        calibration_data = {agent: {'confidences': [], 'correct': []} 
                           for agent in self.agent_names}
        calibration_data['ensemble'] = {'confidences': [], 'correct': []}
        
        for result in results:
            agent_preds = result.get('agent_predictions', {})
            ensemble = result.get('ensemble', {})
            
            # For each agent
            for agent in self.agent_names:
                if agent in agent_preds:
                    conf = agent_preds[agent].get('confidence', 0.5)
                    pred = agent_preds[agent].get('prediction', 0.5)
                    
                    calibration_data[agent]['confidences'].append(conf)
                    # Use prediction extremity as proxy for "correctness"
                    correctness = abs(pred - 0.5) * 2  # 0 to 1 scale
                    calibration_data[agent]['correct'].append(correctness)
            
            # For ensemble
            if ensemble:
                conf = ensemble.get('confidence', 0.5)
                pred = ensemble.get('prediction', 0.5)
                calibration_data['ensemble']['confidences'].append(conf)
                correctness = abs(pred - 0.5) * 2
                calibration_data['ensemble']['correct'].append(correctness)
        
        # Calculate calibration metrics
        calibration_scores = {}
        for entity, data in calibration_data.items():
            if data['confidences'] and data['correct']:
                # Correlation between confidence and correctness
                correlation = np.corrcoef(data['confidences'], data['correct'])[0, 1]
                
                # Binned calibration
                bins = np.linspace(0, 1, 6)
                binned_conf = np.digitize(data['confidences'], bins)
                calibration_error = 0
                
                for i in range(1, len(bins)):
                    mask = binned_conf == i
                    if np.any(mask):
                        avg_conf = np.mean([c for c, m in zip(data['confidences'], mask) if m])
                        avg_correct = np.mean([c for c, m in zip(data['correct'], mask) if m])
                        calibration_error += abs(avg_conf - avg_correct) * np.sum(mask)
                
                calibration_error /= len(data['confidences'])
                
                calibration_scores[entity] = {
                    'correlation': correlation if not np.isnan(correlation) else 0,
                    'calibration_error': calibration_error,
                    'avg_confidence': np.mean(data['confidences']),
                    'confidence_std': np.std(data['confidences'])
                }
        
        return calibration_scores
    
    def _analyze_agent_contributions(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze unique contributions of each agent"""
        contributions = {agent: {
            'influence_on_ensemble': [],
            'unique_high_scores': 0,
            'unique_low_scores': 0,
            'avg_contribution': 0
        } for agent in self.agent_names}
        
        for result in results:
            agent_preds = result.get('agent_predictions', {})
            ensemble_pred = result.get('ensemble', {}).get('prediction', 0.5)
            
            # Calculate each agent's influence
            predictions = []
            for agent in self.agent_names:
                pred = agent_preds.get(agent, {}).get('prediction', 0.5)
                predictions.append(pred)
            
            mean_pred = np.mean(predictions)
            
            for i, agent in enumerate(self.agent_names):
                if agent in agent_preds:
                    agent_pred = agent_preds[agent].get('prediction', 0.5)
                    
                    # Influence: how much this agent pulls the ensemble
                    influence = (agent_pred - mean_pred) * (1 / len(self.agent_names))
                    contributions[agent]['influence_on_ensemble'].append(abs(influence))
                    
                    # Unique insights
                    if agent_pred > 0.7 and ensemble_pred < 0.5:
                        contributions[agent]['unique_high_scores'] += 1
                    elif agent_pred < 0.3 and ensemble_pred > 0.5:
                        contributions[agent]['unique_low_scores'] += 1
        
        # Summarize contributions
        for agent, data in contributions.items():
            if data['influence_on_ensemble']:
                data['avg_contribution'] = np.mean(data['influence_on_ensemble'])
                data['contribution_variance'] = np.var(data['influence_on_ensemble'])
            
            data['unique_insights_total'] = (data['unique_high_scores'] + 
                                            data['unique_low_scores'])
            data['unique_insight_rate'] = data['unique_insights_total'] / len(results)
        
        return contributions
    
    def generate_evaluation_report(self, intelligence_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate comprehensive evaluation report for the multi-agent system
        
        Args:
            intelligence_results: List of intelligence analysis results
            
        Returns:
            Evaluation report
        """
        logger.info("Generating automated evaluation report")
        
        # Extract relevant data for evaluation
        analysis_results = []
        for intel_result in intelligence_results:
            if 'llm_analysis' in intel_result:
                analysis_results.append(intel_result['llm_analysis'])
        
        # Run evaluations
        collaboration_metrics = self.evaluate_agent_collaboration(analysis_results)
        
        # Calculate overall system performance metrics
        system_metrics = self._calculate_system_metrics(intelligence_results)
        
        # Generate visualizations
        viz_data = self._prepare_visualization_data(collaboration_metrics, system_metrics)
        
        # Compile report
        report = {
            'metadata': {
                'evaluation_date': datetime.now().isoformat(),
                'num_cves_evaluated': len(intelligence_results),
                'evaluation_type': 'automated_multi_agent'
            },
            'collaboration_metrics': collaboration_metrics,
            'system_performance': system_metrics,
            'key_findings': self._generate_key_findings(collaboration_metrics, system_metrics),
            'agent_performance_summary': self._summarize_agent_performance(collaboration_metrics),
            'visualization_data': viz_data,
            'recommendations': self._generate_recommendations(collaboration_metrics, system_metrics)
        }
        
        return report
    
    def _calculate_system_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall system performance metrics"""
        quality_scores = []
        coverage_scores = []
        confidence_levels = []
        
        for result in results:
            metadata = result.get('metadata', {})
            quality_scores.append(metadata.get('intelligence_quality_score', 0))
            
            sources = result.get('intelligence_sources', {})
            if sources.get('sources_checked', 0) > 0:
                coverage = sources.get('sources_with_data', 0) / sources['sources_checked']
                coverage_scores.append(coverage)
            
            confidence_levels.append(metadata.get('confidence_level', 'UNKNOWN'))
        
        # Distribution of confidence levels
        confidence_dist = pd.Series(confidence_levels).value_counts().to_dict()
        
        return {
            'avg_quality_score': np.mean(quality_scores),
            'quality_score_std': np.std(quality_scores),
            'avg_coverage': np.mean(coverage_scores),
            'coverage_std': np.std(coverage_scores),
            'confidence_distribution': confidence_dist,
            'high_quality_rate': sum(s > 0.7 for s in quality_scores) / len(quality_scores),
            'low_quality_rate': sum(s < 0.4 for s in quality_scores) / len(quality_scores)
        }
    
    def _generate_key_findings(self, collab_metrics: Dict[str, Any], 
                              system_metrics: Dict[str, Any]) -> List[str]:
        """Generate key findings from the evaluation"""
        findings = []
        
        # Agent collaboration findings
        agreement = collab_metrics['agent_agreement']['overall_agreement']
        if agreement > 0.8:
            findings.append(f"High agent agreement ({agreement:.1%}) indicates consistent analysis")
        elif agreement < 0.6:
            findings.append(f"Low agent agreement ({agreement:.1%}) suggests diverse perspectives")
        
        # Specialization findings
        specialization = collab_metrics['agent_specialization']
        top_specialist = max(specialization.items(), 
                           key=lambda x: x[1]['specialization_score'])
        findings.append(f"{top_specialist[0]} shows highest specialization with "
                       f"{top_specialist[1]['unique_insight_rate']:.1%} unique insights")
        
        # System performance findings
        avg_quality = system_metrics['avg_quality_score']
        findings.append(f"Average intelligence quality: {avg_quality:.1%}")
        
        if system_metrics['high_quality_rate'] > 0.7:
            findings.append("System consistently produces high-quality intelligence reports")
        
        return findings
    
    def _summarize_agent_performance(self, collab_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize individual agent performance"""
        summary = {}
        
        specialization = collab_metrics['agent_specialization']
        calibration = collab_metrics['confidence_calibration']
        contributions = collab_metrics['agent_contribution']
        
        for agent in self.agent_names:
            summary[agent] = {
                'specialization_score': specialization[agent]['specialization_score'],
                'calibration_error': calibration[agent]['calibration_error'],
                'avg_contribution': contributions[agent]['avg_contribution'],
                'unique_insights': contributions[agent]['unique_insights_total'],
                'performance_grade': self._calculate_agent_grade(
                    specialization[agent], 
                    calibration[agent], 
                    contributions[agent]
                )
            }
        
        return summary
    
    def _calculate_agent_grade(self, spec: Dict, calib: Dict, contrib: Dict) -> str:
        """Calculate overall grade for an agent"""
        score = 0
        
        # Specialization (0-40 points)
        score += spec['specialization_score'] * 40
        
        # Calibration (0-30 points)
        score += (1 - calib['calibration_error']) * 30
        
        # Contribution (0-30 points)
        score += min(contrib['avg_contribution'] * 100, 1) * 30
        
        if score >= 85:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 55:
            return 'C'
        else:
            return 'D'
    
    def _prepare_visualization_data(self, collab_metrics: Dict[str, Any],
                                   system_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for visualization"""
        return {
            'agent_agreement_matrix': self._create_agreement_matrix(collab_metrics),
            'quality_distribution': system_metrics['avg_quality_score'],
            'agent_contributions': {
                agent: collab_metrics['agent_contribution'][agent]['avg_contribution']
                for agent in self.agent_names
            },
            'confidence_distribution': system_metrics['confidence_distribution']
        }
    
    def _create_agreement_matrix(self, collab_metrics: Dict[str, Any]) -> Dict[str, float]:
        """Create pairwise agreement matrix for visualization"""
        pairwise = collab_metrics['agent_agreement']['pairwise_agreement']
        
        # Convert to matrix format
        matrix = {}
        for pair, agreement in pairwise.items():
            agents = pair.split('_vs_')
            matrix[f"{agents[0]}-{agents[1]}"] = agreement
        
        return matrix
    
    def _generate_recommendations(self, collab_metrics: Dict[str, Any],
                                system_metrics: Dict[str, Any]) -> List[str]:
        """Generate recommendations for system improvement"""
        recommendations = []
        
        # Based on agreement
        if collab_metrics['agent_agreement']['overall_agreement'] < 0.6:
            recommendations.append("Consider retraining agents for better consensus")
        
        # Based on calibration
        worst_calibrated = max(collab_metrics['confidence_calibration'].items(),
                              key=lambda x: x[1]['calibration_error'])
        if worst_calibrated[1]['calibration_error'] > 0.2:
            recommendations.append(f"Improve confidence calibration for {worst_calibrated[0]}")
        
        # Based on quality
        if system_metrics['low_quality_rate'] > 0.3:
            recommendations.append("Investigate sources of low-quality intelligence reports")
        
        # Based on coverage
        if system_metrics['avg_coverage'] < 0.5:
            recommendations.append("Expand intelligence sources for better coverage")
        
        return recommendations