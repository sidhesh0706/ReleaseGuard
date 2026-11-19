import json
import unittest
from pathlib import Path

from engine import assess


PATCH = """--- /dev/null
+++ b/src/checkout.js
@@ -0,0 +1,4 @@
+import telemetry from "@demo/telemetry";
+const payload = { email: customer.email };
+telemetry.track(payload);
+const reviewComplete = true;
"""


def lock(version, resolved="https://registry.example.invalid/replay", integrity="sha512-fixture"):
    return json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"@demo/telemetry": "1.0.0"}},
            "node_modules/@demo/telemetry": {"version": "1.0.0", "dependencies": {"demo-replay": "*"}},
            "node_modules/demo-replay": {"version": version, "resolved": resolved, "integrity": integrity},
        },
    })


class DependencyEvidenceTests(unittest.TestCase):
    def test_changed_transitive_under_unchanged_direct_package(self):
        report = assess(PATCH, baseline_lock=lock("1.0.0"), release_lock=lock("1.0.1"))
        lock_summary = report["dependency_changes"]
        self.assertEqual((lock_summary["direct"], lock_summary["transitive"]), (0, 1))
        self.assertEqual(report["privacy_routes"][0]["chain"], ["@demo/telemetry", "demo-replay"])
        self.assertEqual(report["privacy_routes"][0]["line"], 3)

    def test_shared_transitive_traces_the_package_at_the_sink(self):
        before, after = json.loads(lock("1.0.0")), json.loads(lock("1.0.1"))
        for manifest in (before, after):
            packages = manifest["packages"]
            packages[""]["dependencies"]["aaa-observability"] = "*"
            packages["node_modules/aaa-observability"] = {"version": "1.0.0", "dependencies": {"demo-replay": "*"}}
        report = assess(PATCH, baseline_lock=json.dumps(before), release_lock=json.dumps(after))
        self.assertEqual(report["privacy_routes"][0]["chain"], ["@demo/telemetry", "demo-replay"])

    def test_export_omits_raw_registry_urls_and_hashes(self):
        exported = json.dumps(assess(PATCH, baseline_lock=lock("1.0.0"),
                            release_lock=lock("1.0.1", "https://registry.example.invalid/internal-package", "sha512-new-fixture")))
        self.assertNotIn("registry.example.invalid", exported)
        self.assertNotIn("sha512-new-fixture", exported)

    def test_invalid_lock_metadata_is_a_validation_error(self):
        with self.assertRaisesRegex(ValueError, "valid npm package-lock"):
            assess(PATCH, baseline_lock=lock("1.0.0"), release_lock=lock("1.0.1", {}))

    def test_clean_reassignment_clears_candidate_field(self):
        patch = PATCH.replace("+telemetry.track(payload);\n+const reviewComplete = true;",
                              "+payload = { status: 'ok' };\n+telemetry.track(payload);")
        self.assertFalse(assess(patch, baseline_lock=lock("1.0.0"), release_lock=lock("1.0.1"))["privacy_routes"])

    def test_bundled_demo_exercises_all_evidence_types(self):
        demo = json.loads(Path(__file__).with_name("web").joinpath("demo.json").read_text(encoding="utf-8"))
        report = assess(**{key: artifact["text"] for key, artifact in demo.items()})
        self.assertEqual(report["decision"], "HOLD")
        self.assertTrue(report["coverage"]["supplied"])
        self.assertTrue(report["incidents"])
        self.assertEqual(report["network"]["flagged"], 2)
        self.assertEqual(report["npm_audit"]["transitive"], 1)
        self.assertTrue(report["privacy_routes"])

    def test_moderate_risk_demo_returns_canary(self):
        fixture = Path(__file__).with_name("web") / "demo-moderate.json"
        demo = json.loads(fixture.read_text(encoding="utf-8"))
        report = assess(**{key: artifact["text"] for key, artifact in demo.items()})
        self.assertEqual(report["decision"], "CANARY")
        self.assertFalse(report["blockers"])


    def test_payment_retry_demo_matches_coverage_and_incident(self):
        fixture = Path(__file__).with_name("web") / "demo-payments.json"
        demo = json.loads(fixture.read_text(encoding="utf-8"))
        report = assess(**{key: artifact["text"] for key, artifact in demo.items()})
        self.assertEqual(report["decision"], "CANARY")
        self.assertEqual((report["coverage"]["covered"], report["coverage"]["missed"]), (8, 1))
        self.assertEqual([incident["id"] for incident in report["incidents"]], ["INC-204"])
        self.assertFalse(report["blockers"])

    def test_fully_covered_receipt_label_demo_returns_go(self):
        fixture = Path(__file__).with_name("web") / "demo-go.json"
        demo = json.loads(fixture.read_text(encoding="utf-8"))
        report = assess(**{key: artifact["text"] for key, artifact in demo.items()})
        self.assertEqual(report["decision"], "GO")
        self.assertEqual(report["coverage"]["percent"], 100)
        self.assertFalse(report["blockers"])


if __name__ == "__main__":
    unittest.main()
