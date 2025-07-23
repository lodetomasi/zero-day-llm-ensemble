"""
Debug utilities for Zero-Day Detection System
"""
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import pandas as pd
from pathlib import Path

from config.settings import DEBUG_MODE, SAVE_INTERMEDIATE_RESULTS, RESULTS_DIR


class DebugTracker:
    """Track and debug LLM responses and predictions"""
    
    def __init__(self):
        self.api_calls = []
        self.response_times = []
        self.token_usage = []
        self.predictions = []
        self.errors = []
        
        if SAVE_INTERMEDIATE_RESULTS:
            self.debug_dir = RESULTS_DIR / "debug"
            self.debug_dir.mkdir(exist_ok=True)
    
    def track_api_call(self, agent_name: str, model: str, cve_id: str, 
                      prompt: str, response: str, tokens: Dict[str, int], 
                      duration: float, prediction: Dict[str, float]):
        """Track detailed API call information"""
        call_data = {
            'timestamp': datetime.now().isoformat(),
            'agent_name': agent_name,
            'model': model,
            'cve_id': cve_id,
            'prompt_length': len(prompt),
            'prompt_preview': prompt[:500],
            'response_length': len(response),
            'response_preview': response[:500],
            'tokens': tokens,
            'duration': duration,
            'prediction': prediction
        }
        
        self.api_calls.append(call_data)
        self.response_times.append(duration)
        self.token_usage.append(tokens.get('total', 0))
        
        if SAVE_INTERMEDIATE_RESULTS and len(self.api_calls) % 10 == 0:
            self._save_intermediate()
    
    def track_error(self, agent_name: str, model: str, error: Exception, 
                   context: Dict[str, Any]):
        """Track errors for debugging"""
        error_data = {
            'timestamp': datetime.now().isoformat(),
            'agent_name': agent_name,
            'model': model,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context
        }
        self.errors.append(error_data)
    
    def analyze_predictions(self, ground_truth: List[int]) -> Dict[str, Any]:
        """Analyze prediction patterns for debugging"""
        if not self.predictions:
            return {}
        
        df = pd.DataFrame(self.predictions)
        
        analysis = {
            'total_predictions': len(df),
            'avg_confidence': df['confidence'].mean(),
            'prediction_distribution': df['prediction'].value_counts().to_dict(),
            'agent_agreement': self._calculate_agent_agreement(df),
            'problematic_cases': self._identify_problematic_cases(df, ground_truth)
        }
        
        return analysis
    
    def _calculate_agent_agreement(self, df: pd.DataFrame) -> Dict[str, float]:
        """Calculate agreement between agents"""
        if 'agent_predictions' not in df.columns:
            return {}
        
        # Calculate pairwise agreement
        agreement_scores = {}
        agent_names = list(df.iloc[0]['agent_predictions'].keys())
        
        for i, agent1 in enumerate(agent_names):
            for agent2 in agent_names[i+1:]:
                agreements = []
                for _, row in df.iterrows():
                    pred1 = row['agent_predictions'].get(agent1, {}).get('prediction', 0.5)
                    pred2 = row['agent_predictions'].get(agent2, {}).get('prediction', 0.5)
                    # Binary agreement
                    agreements.append(int((pred1 > 0.5) == (pred2 > 0.5)))
                
                agreement_scores[f"{agent1}_vs_{agent2}"] = sum(agreements) / len(agreements)
        
        return agreement_scores
    
    def _identify_problematic_cases(self, df: pd.DataFrame, 
                                   ground_truth: List[int]) -> List[Dict[str, Any]]:
        """Identify cases where prediction was wrong or confidence was low"""
        problematic = []
        
        for i, (_, row) in enumerate(df.iterrows()):
            if i >= len(ground_truth):
                break
            
            prediction = int(row['prediction'] > 0.5)
            true_label = ground_truth[i]
            
            # Wrong prediction or low confidence
            if prediction != true_label or row['confidence'] < 0.6:
                problematic.append({
                    'cve_id': row['cve_id'],
                    'prediction': row['prediction'],
                    'true_label': true_label,
                    'confidence': row['confidence'],
                    'correct': prediction == true_label
                })
        
        return problematic
    
    def _save_intermediate(self):
        """Save intermediate results for debugging"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save API calls
        with open(self.debug_dir / f"api_calls_{timestamp}.json", 'w') as f:
            json.dump(self.api_calls[-100:], f, indent=2)  # Last 100 calls
        
        # Save summary statistics
        stats = {
            'total_api_calls': len(self.api_calls),
            'avg_response_time': sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            'total_tokens': sum(self.token_usage),
            'errors': len(self.errors)
        }
        
        with open(self.debug_dir / f"stats_{timestamp}.json", 'w') as f:
            json.dump(stats, f, indent=2)
    
    def generate_debug_report(self) -> str:
        """Generate comprehensive debug report"""
        report = []
        report.append("=" * 60)
        report.append("DEBUG REPORT - Zero-Day Detection System")
        report.append("=" * 60)
        
        # API Call Statistics
        report.append("\nAPI CALL STATISTICS:")
        report.append(f"Total API calls: {len(self.api_calls)}")
        if self.response_times:
            report.append(f"Average response time: {sum(self.response_times)/len(self.response_times):.2f}s")
            report.append(f"Min/Max response time: {min(self.response_times):.2f}s / {max(self.response_times):.2f}s")
        
        # Token Usage
        if self.token_usage:
            report.append(f"\nTOKEN USAGE:")
            report.append(f"Total tokens used: {sum(self.token_usage):,}")
            report.append(f"Average tokens per call: {sum(self.token_usage)/len(self.token_usage):.0f}")
        
        # Error Analysis
        if self.errors:
            report.append(f"\nERRORS ({len(self.errors)} total):")
            error_types = {}
            for error in self.errors:
                error_type = error['error_type']
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            for error_type, count in error_types.items():
                report.append(f"  {error_type}: {count}")
        
        # Model Performance
        if self.api_calls:
            report.append("\nMODEL USAGE:")
            model_counts = {}
            for call in self.api_calls:
                model = call['model']
                model_counts[model] = model_counts.get(model, 0) + 1
            
            for model, count in model_counts.items():
                report.append(f"  {model}: {count} calls")
        
        return "\n".join(report)


class PromptDebugger:
    """Debug and analyze prompt effectiveness"""
    
    def __init__(self):
        self.prompt_responses = []
    
    def analyze_prompt_response(self, prompt: str, response: str, 
                               expected_format: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze if response matches expected format"""
        analysis = {
            'prompt_length': len(prompt),
            'response_length': len(response),
            'contains_prediction': self._check_prediction_format(response),
            'contains_confidence': self._check_confidence_format(response),
            'format_compliance': self._check_format_compliance(response, expected_format)
        }
        
        return analysis
    
    def _check_prediction_format(self, response: str) -> bool:
        """Check if response contains prediction in expected format"""
        import re
        patterns = [
            r'prediction[:\s]*([0-9.]+)',
            r'score[:\s]*([0-9.]+)',
            r'\b([0-9.]+)\s*(?:prediction|score)',
        ]
        
        for pattern in patterns:
            if re.search(pattern, response.lower()):
                return True
        return False
    
    def _check_confidence_format(self, response: str) -> bool:
        """Check if response contains confidence in expected format"""
        import re
        patterns = [
            r'confidence[:\s]*([0-9.]+)',
            r'certainty[:\s]*([0-9.]+)',
        ]
        
        for pattern in patterns:
            if re.search(pattern, response.lower()):
                return True
        return False
    
    def _check_format_compliance(self, response: str, 
                                expected_format: Dict[str, Any]) -> float:
        """Check how well response matches expected format"""
        compliance_score = 0.0
        total_checks = 0
        
        for key, expected_type in expected_format.items():
            total_checks += 1
            if key.lower() in response.lower():
                compliance_score += 0.5
                
                # Check for appropriate content
                if expected_type == 'number' and any(c.isdigit() for c in response):
                    compliance_score += 0.5
                elif expected_type == 'list' and any(marker in response for marker in ['1.', '-', '*']):
                    compliance_score += 0.5
                elif expected_type == 'text':
                    compliance_score += 0.5
        
        return compliance_score / total_checks if total_checks > 0 else 0.0


# Global debug tracker
debug_tracker = DebugTracker()
prompt_debugger = PromptDebugger()