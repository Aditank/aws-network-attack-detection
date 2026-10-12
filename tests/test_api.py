"""
Integration & End-to-End API Tests for Flask Application.
Tests health checks, CSV uploads, schema resilience, and edge case error handling.
"""

import unittest
import io
import json
import pandas as pd
from app import app

class TestFlaskAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_health_check_endpoint(self):
        """GET /api/health should return 200 with healthy status."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_sample_csv_endpoint(self):
        """GET /api/sample should return a valid downloadable CSV file."""
        response = self.client.get("/api/sample")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.content_type)
        self.assertIn("attachment; filename=traffic_sample.csv", response.headers.get("Content-Disposition", ""))

    def test_detect_valid_csv(self):
        """POST /api/detect with valid traffic flow should return 200 and detection summaries."""
        df = pd.DataFrame({
            "Destination Port": [80, 22, 443],
            "Flow Duration": [200, 5000, 15000],
            "Total Fwd Packets": [1, 25, 8],
            "Total Backward Packets": [0, 10, 8],
            "Flow Packets/s": [50, 20, 30],
            "Flow Bytes/s": [100, 5000, 12000],
            "SYN Flag Count": [1, 0, 0],
            "ACK Flag Count": [0, 1, 1]
        })
        csv_bytes = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
        data = {"file": (csv_bytes, "traffic_test.csv")}

        response = self.client.post("/api/detect", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        
        payload = response.get_json()
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["summary"]["total_records"], 3)
        self.assertIn("ml_detected_attacks", payload["summary"])
        self.assertIn("rule_detected_attacks", payload["summary"])
        self.assertIn("suspicious_records", payload)

    def test_detect_no_file_uploaded(self):
        """POST /api/detect without file parameter should return 400 Bad Request."""
        response = self.client.post("/api/detect", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_detect_invalid_file_extension(self):
        """POST /api/detect with non-CSV file should return 400 Bad Request."""
        text_file = io.BytesIO(b"Hello network traffic")
        data = {"file": (text_file, "notes.txt")}

        response = self.client.post("/api/detect", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid file format", response.get_json()["error"])

    def test_detect_empty_file(self):
        """POST /api/detect with 0-byte file should return 400 Bad Request."""
        empty_file = io.BytesIO(b"")
        data = {"file": (empty_file, "empty.csv")}

        response = self.client.post("/api/detect", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertIn("empty", response.get_json()["error"].lower())

    def test_detect_arbitrary_columns_resilience(self):
        """POST /api/detect with non-standard column names should not crash."""
        df = pd.DataFrame({
            "dst_port": [80, 443],
            "dur": [500, 1000],
            "fwd_pkts": [1, 2]
        })
        csv_bytes = io.BytesIO(df.to_csv(index=False).encode("utf-8"))
        data = {"file": (csv_bytes, "arbitrary.csv")}

        response = self.client.post("/api/detect", data=data, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["summary"]["total_records"], 2)

if __name__ == "__main__":
    unittest.main()
