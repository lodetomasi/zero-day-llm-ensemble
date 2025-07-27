"""
Base agent class for Zero-Day Detection System
"""
import time
import yaml
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import requests

from config.settings import (
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL, 
    MAX_RETRIES, RETRY_DELAY, REQUEST_TIMEOUT,
    CONFIG_DIR
)
from src.utils.logger import api_logger, get_logger
from src.utils.debug import debug_tracker, prompt_debugger
from src.utils.credit_monitor import credit_monitor

logger = get_logger(__name__)


class BaseAgent:
    """Base class for all LLM agents"""
    
    def __init__(self, agent_name: str, model_id: str):
        self.agent_name = agent_name
        self.model_id = model_id
        
        # Load prompts
        self.prompts = self._load_prompts()
        
        # API configuration
        self.headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:8888",
            "X-Title": "Zero-Day-Detection-Research"
        }
        
        # Performance tracking
        self.call_count = 0
        self.total_tokens = 0
        self.total_time = 0.0
        self.errors = 0
    
    def _load_prompts(self) -> Dict[str, Any]:
        """Load prompts from YAML configuration"""
        prompt_file = CONFIG_DIR / "prompts.yaml"
        
        try:
            with open(prompt_file, 'r') as f:
                all_prompts = yaml.safe_load(f)
                
            agent_prompts = all_prompts['prompts'].get(self.agent_name, {})
            parameters = all_prompts.get('parameters', {})
            
            return {
                'system_prompt': agent_prompts.get('system_prompt', ''),
                'analysis_template': agent_prompts.get('analysis_template', ''),
                'source_contexts': agent_prompts.get('source_contexts', {}),
                'parameters': parameters
            }
        except Exception as e:
            logger.error(f"Failed to load prompts for {self.agent_name}: {e}")
            return {
                'system_prompt': f"You are {self.agent_name} analyzing CVE vulnerabilities.",
                'analysis_template': "Analyze the CVE: {cve_id}",
                'source_contexts': {},
                'parameters': {}
            }
    
    def create_prompt(self, cve_data: Dict[str, Any]) -> str:
        """Create prompt from template and CVE data"""
        # Get source-specific context
        source = cve_data.get('source', 'Unknown')
        source_context = self.prompts['source_contexts'].get(
            source, 
            f"Source: {source}"
        )
        
        # Prepare template variables
        template_vars = {
            'cve_id': cve_data.get('cve_id', 'Unknown'),
            'vendor': cve_data.get('vendor', 'Unknown'),
            'product': cve_data.get('product', 'Unknown'),
            'description': cve_data.get('description', 'No description available'),
            'source': source,
            'year': cve_data.get('year', 'Unknown'),
            'published_date': cve_data.get('published_date', 'Unknown'),
            'last_modified': cve_data.get('last_modified', 'Unknown'),
            'date_added': cve_data.get('date_added', 'Unknown'),
            'due_date': cve_data.get('due_date', 'Unknown'),
            'required_action': cve_data.get('required_action', 'No action specified'),
            'source_context': source_context
        }
        
        # Format the template
        try:
            prompt = self.prompts['analysis_template'].format(**template_vars)
        except KeyError as e:
            logger.warning(f"Missing template variable: {e}")
            # Fallback to simple prompt
            prompt = f"""
            Analyze this CVE for zero-day indicators:
            CVE: {template_vars['cve_id']}
            Source: {template_vars['source']}
            Description: {template_vars['description']}
            {source_context}
            """
        
        return prompt
    
    def parse_response(self, response: str, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse LLM response to extract prediction and confidence"""
        response_lower = response.lower()
        
        # Initialize default values
        prediction = 0.5
        confidence = 0.5
        reasoning = response[:500]
        
        # Extract prediction score
        pred_patterns = [
            r'prediction[:\s]*([0-9]*\.?[0-9]+)',
            r'score[:\s]*([0-9]*\.?[0-9]+)',
            r'likelihood[:\s]*([0-9]*\.?[0-9]+)',
            r'probability[:\s]*([0-9]*\.?[0-9]+)',
            r'\b([0-9]*\.?[0-9]+)\s*(?:/\s*1\.0)?(?:\s*prediction)?'
        ]
        
        for pattern in pred_patterns:
            match = re.search(pattern, response_lower)
            if match:
                try:
                    score = float(match.group(1))
                    if 0 <= score <= 1:
                        prediction = score
                        break
                    elif 0 <= score <= 100:
                        prediction = score / 100
                        break
                except ValueError:
                    continue
        
        # Extract confidence score
        conf_patterns = [
            r'confidence[:\s]*([0-9]*\.?[0-9]+)',
            r'certainty[:\s]*([0-9]*\.?[0-9]+)',
            r'confident[:\s]*([0-9]*\.?[0-9]+)%?'
        ]
        
        for pattern in conf_patterns:
            match = re.search(pattern, response_lower)
            if match:
                try:
                    conf = float(match.group(1))
                    if 0 <= conf <= 1:
                        confidence = conf
                        break
                    elif 0 <= conf <= 100:
                        confidence = conf / 100
                        break
                except ValueError:
                    continue
        
        # DISABLED: Source-based adjustments to avoid bias
        # Let the model classify based on content, not source
        
        # Check for explicit zero-day mentions
        if any(term in response_lower for term in ['confirmed zero-day', 'definitely zero-day', 'certainly zero-day']):
            prediction = max(prediction, 0.9)
            confidence = max(confidence, 0.8)
        elif any(term in response_lower for term in ['not zero-day', 'regular cve', 'standard vulnerability']):
            prediction = min(prediction, 0.2)
            confidence = max(confidence, 0.7)
        
        # DISABLED: NVD adjustments to avoid bias
        # Let the model classify based on content alone
        
        # Extract reasoning
        reasoning_patterns = [
            r'reasoning[:\s]*(.+?)(?:prediction|confidence|$)',
            r'explanation[:\s]*(.+?)(?:prediction|confidence|$)',
            r'analysis[:\s]*(.+?)(?:prediction|confidence|$)'
        ]
        
        for pattern in reasoning_patterns:
            match = re.search(pattern, response_lower, re.DOTALL)
            if match:
                reasoning = match.group(1).strip()[:500]
                break
        
        return {
            'prediction': max(0.0, min(1.0, prediction)),
            'confidence': max(0.0, min(1.0, confidence)),
            'reasoning': reasoning,
            'raw_response': response
        }
    
    def analyze(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a CVE and return prediction"""
        self.call_count += 1
        
        # Check if model has exhausted credits
        if not credit_monitor.is_available(self.model_id):
            logger.warning(f"{self.agent_name} skipped - credits exhausted for {self.model_id}")
            return {
                'prediction': 0.5,  # Neutral prediction when no credits
                'confidence': 0.1,  # Very low confidence
                'reasoning': "Model credits exhausted - unable to analyze",
                'error': True,
                'error_type': 'credits_skip'
            }
        
        # Create prompt
        prompt = self.create_prompt(cve_data)
        
        # Debug prompt if needed
        if self.call_count <= 5:
            logger.debug(f"{self.agent_name} prompt preview: {prompt[:200]}...")
        
        # Make API call
        for attempt in range(MAX_RETRIES):
            try:
                # Log API request
                api_logger.log_api_request(
                    self.model_id, 
                    prompt, 
                    cve_data.get('cve_id', 'Unknown'),
                    self.agent_name
                )
                
                # Prepare payload
                payload = {
                    "model": self.model_id,
                    "messages": [
                        {"role": "system", "content": self.prompts['system_prompt']},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": self.prompts['parameters'].get('temperature', 0.1),
                    "max_tokens": self.prompts['parameters'].get('max_tokens', 500),
                    "top_p": self.prompts['parameters'].get('top_p', 0.95)
                }
                
                # Make request
                start_time = time.time()
                response = requests.post(
                    f"{OPENROUTER_BASE_URL}/chat/completions",
                    headers=self.headers,
                    json=payload,
                    timeout=REQUEST_TIMEOUT
                )
                duration = time.time() - start_time
                self.total_time += duration
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Extract response content
                    content = result['choices'][0]['message']['content'].strip()
                    usage = result.get('usage', {})
                    
                    # Update token usage
                    tokens_used = usage.get('total_tokens', 0)
                    self.total_tokens += tokens_used
                    
                    # Log API response
                    api_logger.log_api_response(
                        self.model_id,
                        {'status': 'success'},
                        usage,
                        duration
                    )
                    
                    # Parse response
                    parsed = self.parse_response(content, cve_data)
                    
                    # Track for debugging
                    debug_tracker.track_api_call(
                        self.agent_name,
                        self.model_id,
                        cve_data.get('cve_id', 'Unknown'),
                        prompt,
                        content,
                        usage,
                        duration,
                        parsed
                    )
                    
                    return parsed
                    
                else:
                    error_msg = f"API error: {response.status_code} - {response.text}"
                    raise Exception(error_msg)
                    
            except Exception as e:
                self.errors += 1
                api_logger.log_api_error(self.model_id, e, attempt + 1)
                debug_tracker.track_error(
                    self.agent_name,
                    self.model_id,
                    e,
                    {'cve_id': cve_data.get('cve_id', 'Unknown'), 'attempt': attempt + 1}
                )
                
                # Check if it's a credit/quota error
                error_str = str(e).lower()
                if '402' in error_str or 'credit' in error_str or 'quota' in error_str:
                    logger.error(f"{self.agent_name} API credits exhausted: {e}")
                    # Mark model as exhausted
                    credit_monitor.mark_exhausted(self.model_id)
                    # Return a conservative prediction for credit errors
                    return {
                        'prediction': 0.3 if cve_data.get('source') == 'NVD' else 0.7,
                        'confidence': 0.3,
                        'reasoning': f"API credits exhausted - using conservative estimate",
                        'error': True,
                        'error_type': 'credits'
                    }
                
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.error(f"{self.agent_name} failed after {MAX_RETRIES} attempts")
                    # Return fallback prediction
                    return {
                        'prediction': 0.5,
                        'confidence': 0.1,
                        'reasoning': f"API error: {str(e)}",
                        'error': True
                    }
        
        return {
            'prediction': 0.5,
            'confidence': 0.1,
            'reasoning': "Failed to get response",
            'error': True
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get agent performance statistics"""
        avg_time = self.total_time / self.call_count if self.call_count > 0 else 0
        avg_tokens = self.total_tokens / self.call_count if self.call_count > 0 else 0
        
        return {
            'agent_name': self.agent_name,
            'model_id': self.model_id,
            'total_calls': self.call_count,
            'total_errors': self.errors,
            'error_rate': self.errors / self.call_count if self.call_count > 0 else 0,
            'total_tokens': self.total_tokens,
            'avg_tokens_per_call': avg_tokens,
            'total_time': self.total_time,
            'avg_time_per_call': avg_time
        }