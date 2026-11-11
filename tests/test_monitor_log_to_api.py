import json
import unittest

from tools.monitor_log_to_api import convert


def window(start, count, attack):
    return {"record_type": "window", "window_start": start, "window_end": start + 1, "packet_count": count,
            "logged_at": start + 1.001, "scored": True, "attack_score": 0.9 if attack else 0.1,
            "predicted_attack": attack}


class ConvertTests(unittest.TestCase):
    def snapshot(self, status="completed"):
        lines = [{"record_type": "monitor_status", "status": status, "logged_at": 1.0, "model_sha256": "ab" * 32,
                  "data_kind": "synthetic"}, window(10.0, 20, False), window(11.0, 400, True),
                 {"record_type": "monitor_status", "status": status, "logged_at": 13.0, "model_sha256": "ab" * 32,
                  "data_kind": "synthetic"}]
        return convert(json.dumps(line) for line in lines)

    def test_shapes_and_monitor_only(self):
        snap = self.snapshot()
        self.assertEqual(snap["health"]["mitigation_mode"], "monitor_only")
        self.assertEqual(snap["health"]["capture_status"], "stopped")
        self.assertEqual([p["packets_per_second"] for p in snap["metrics"]["points"]], [20, 400])
        self.assertIsNone(snap["metrics"]["points"][0]["bytes_per_second"])
        self.assertEqual(snap["blocks"]["blocks"], [])

    def test_alerts_are_aggregate_only(self):
        (det,) = self.snapshot()["detections"]["detections"]
        self.assertEqual((det["scope"], det["decision"], det["source_ip"]), ("aggregate", "alert", None))

    def test_unavailable_status_is_error(self):
        self.assertEqual(self.snapshot("unavailable")["health"]["capture_status"], "error")

    def test_requires_status(self):
        with self.assertRaises(ValueError):
            convert([json.dumps(window(1.0, 1, False))])


if __name__ == "__main__":
    unittest.main()
