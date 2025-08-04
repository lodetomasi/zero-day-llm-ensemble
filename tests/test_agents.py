#!/usr/bin/env python3
"""
Unit tests for LLM agents
"""
import unittest
from unittest.mock import Mock, patch
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.agents.base_agent import BaseAgent
from src.agents.forensic import ForensicAnalyst
from src.ensemble.multi_agent import MultiAgentSystem


class TestBaseAgent(unittest.TestCase):
    """Test base agent functionality"""
    
    def setUp(self):
        """Set up test agent"""
        self.agent = BaseAgent("TestAgent", "test-model")
        
    def test_agent_initialization(self):
        """Test agent initializes correctly"""
        self.assertEqual(self.agent.agent_name, "TestAgent")
        self.assertEqual(self.agent.model_id, "test-model")
        self.assertIsNotNone(self.agent.prompts)
        
    def test_parse_response(self):
        """Test response parsing"""
        test_response = """
        After analyzing the CVE, I believe this is a zero-day vulnerability.
        Prediction: 0.85
        Confidence: 0.90
        Reasoning: The vulnerability shows signs of active exploitation.
        """
        
        cve_data = {"cve_id": "CVE-TEST-0001"}
        result = self.agent.parse_response(test_response, cve_data)
        
        self.assertEqual(result['prediction'], 0.85)
        self.assertEqual(result['confidence'], 0.90)
        self.assertIn("active exploitation", result['reasoning'])


class TestMultiAgentSystem(unittest.TestCase):
    """Test multi-agent ensemble"""
    
    def setUp(self):
        """Set up test system"""
        self.system = MultiAgentSystem(use_thompson_sampling=False)
        
    def test_system_initialization(self):
        """Test system initializes with all agents"""
        self.assertEqual(len(self.system.agents), 5)
        self.assertIn('ForensicAnalyst', self.system.agents)
        self.assertIn('PatternDetector', self.system.agents)
        self.assertIn('TemporalAnalyst', self.system.agents)
        self.assertIn('AttributionExpert', self.system.agents)
        self.assertIn('MetaAnalyst', self.system.agents)
        
    def test_ensemble_prediction(self):
        """Test ensemble prediction calculation"""
        # Mock agent results
        agent_results = {
            'ForensicAnalyst': {'prediction': 0.8, 'confidence': 0.9},
            'PatternDetector': {'prediction': 0.7, 'confidence': 0.8},
            'TemporalAnalyst': {'prediction': 0.9, 'confidence': 0.85},
            'AttributionExpert': {'prediction': 0.75, 'confidence': 0.7},
            'MetaAnalyst': {'prediction': 0.8, 'confidence': 0.8}
        }
        
        result = self.system.ensemble_prediction(agent_results)
        
        # Check ensemble prediction is within expected range
        self.assertGreater(result['prediction'], 0.7)
        self.assertLess(result['prediction'], 0.9)
        self.assertIn('agreement', result)
        self.assertIn('confidence', result)


class TestFeatureExtraction(unittest.TestCase):
    """Test feature extraction"""
    
    def test_temporal_features(self):
        """Test temporal feature extraction"""
        from src.utils.feature_extractor import ZeroDayFeatureExtractor
        
        extractor = ZeroDayFeatureExtractor()
        
        # Mock evidence data
        evidence = {
            'sources': {
                'nvd': {
                    'published_date': '2024-01-01'
                },
                'cisa_kev': {
                    'in_kev': True,
                    'date_added': '2024-01-03'
                }
            }
        }
        
        features = extractor.extract_temporal_features(evidence)
        
        self.assertIn('days_to_kev', features)
        self.assertIn('rapid_kev_addition', features)
        self.assertEqual(features['days_to_kev'], 2.0)
        self.assertEqual(features['rapid_kev_addition'], 1.0)


if __name__ == '__main__':
    unittest.main()