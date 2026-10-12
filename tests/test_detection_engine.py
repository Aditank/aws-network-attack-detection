"""
Unit Tests for Rule Engine and Machine Learning Classifier.
Verifies detection accuracy, edge case handling, and feature alignment.
"""

import unittest
import os
import joblib
import pandas as pd
import numpy as np

from src.rule_engine import RuleBasedEngine

class TestDetectionEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = RuleBasedEngine()
        cls.model_path = os.path.join(os.path.dirname(__file__), "..", "models", "random_forest_model.joblib")
        if os.path.exists(cls.model_path):
            cls.model_bundle = joblib.load(cls.model_path)
        else:
            cls.model_bundle = None

    def test_rule_engine_ddos_detection(self):
        """Rule engine should flag high SYN rate + high packet count as DDoS."""
        flow = {
            "Destination Port": 80,
            "Total Fwd Packets": 500,
            "Total Backward Packets": 2,
            "Flow Packets/s": 800,
            "SYN Flag Count": 1,
            "ACK Flag Count": 0,
            "Flow Duration": 5000,
            "Flow Bytes/s": 50000
        }
        is_attack, attack_type, rule_name = self.engine.predict_record(flow)
        self.assertEqual(is_attack, 1)
        self.assertEqual(attack_type, "DDoS")
        self.assertEqual(rule_name, "RULE_DDOS_HIGH_SYN_RATE")

    def test_rule_engine_portscan_detection(self):
        """Rule engine should flag short duration single SYN packet as PortScan."""
        flow = {
            "Destination Port": 445,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Flow Duration": 200,
            "SYN Flag Count": 1,
            "ACK Flag Count": 0,
            "Flow Packets/s": 50,
            "Flow Bytes/s": 100
        }
        is_attack, attack_type, rule_name = self.engine.predict_record(flow)
        self.assertEqual(is_attack, 1)
        self.assertEqual(attack_type, "PortScan")
        self.assertEqual(rule_name, "RULE_PORTSCAN_SINGLE_SYN")

    def test_rule_engine_ssh_bruteforce_detection(self):
        """Rule engine should flag persistent port 22 connections as SSH attack."""
        flow = {
            "Destination Port": 22,
            "Total Fwd Packets": 30,
            "Total Backward Packets": 15,
            "Flow Duration": 5000,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1,
            "Flow Packets/s": 20,
            "Flow Bytes/s": 5000
        }
        is_attack, attack_type, rule_name = self.engine.predict_record(flow)
        self.assertEqual(is_attack, 1)
        self.assertEqual(attack_type, "SSH-Patator")
        self.assertEqual(rule_name, "RULE_SSH_PATATOR")

    def test_rule_engine_benign_traffic(self):
        """Rule engine should allow standard web traffic as BENIGN."""
        flow = {
            "Destination Port": 443,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 12,
            "Flow Duration": 25000,
            "SYN Flag Count": 0,
            "ACK Flag Count": 1,
            "Flow Packets/s": 50,
            "Flow Bytes/s": 15000
        }
        is_attack, attack_type, rule_name = self.engine.predict_record(flow)
        self.assertEqual(is_attack, 0)
        self.assertEqual(attack_type, "BENIGN")

    def test_rule_engine_resilience_missing_values(self):
        """Rule engine must handle missing or null attributes without crashing."""
        flow = {"dst_port": "80", "packets": None}
        is_attack, attack_type, rule = self.engine.predict_record(flow)
        self.assertIn(is_attack, [0, 1])

    def test_ml_model_bundle_integrity(self):
        """Model artifact must contain trained model, feature names, and evaluation metrics."""
        self.assertIsNotNone(self.model_bundle, "Model file not found. Run src/train_model.py first.")
        self.assertIn("model", self.model_bundle)
        self.assertIn("feature_names", self.model_bundle)
        self.assertIn("metrics", self.model_bundle)
        self.assertGreater(len(self.model_bundle["feature_names"]), 50)
        self.assertGreater(self.model_bundle["metrics"]["accuracy"], 0.90)

    def test_ml_model_prediction(self):
        """Trained ML model should output valid binary predictions and probability scores."""
        if self.model_bundle is None:
            self.skipTest("ML Model not loaded.")
        features = self.model_bundle["feature_names"]
        dummy_data = pd.DataFrame(np.zeros((3, len(features))), columns=features)
        
        preds = self.model_bundle["model"].predict(dummy_data)
        probs = self.model_bundle["model"].predict_proba(dummy_data)
        
        self.assertEqual(len(preds), 3)
        self.assertEqual(probs.shape, (3, 2))
        self.assertTrue(all(p in [0, 1] for p in preds))

if __name__ == "__main__":
    unittest.main()
