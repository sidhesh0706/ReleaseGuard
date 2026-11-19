import json
import unittest

from engine import assess, compare_npm_locks, parse_patch


class AssessmentTests(unittest.TestCase):
    def test_rejects_truncated_hunk_before_following_hunk(self):
        patch = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n+++ b/app.py\n"
            "@@ -1 +1,2 @@\n old\n"
            "@@ -4 +5 @@\n-old\n+new\n"
        )
        with self.assertRaisesRegex(ValueError, "hunk"):
            parse_patch(patch)

    def test_unknown_coverage_counts_in_percentage_denominator(self):
        patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+value = 1\n"
        report = assess(patch)
        self.assertEqual(report["coverage"]["unknown"], 1)
        self.assertEqual(report["coverage"]["percent"], 0)
        self.assertEqual(report["decision"], "CANARY")

    def test_high_severity_finding_cannot_result_in_go(self):
        patch = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -0,0 +1 @@\n+requests.get(url, verify=False)\n"
        report = assess(patch)
        self.assertEqual(report["decision"], "CANARY")

    def test_transitive_lockfile_change_is_traced_and_reviewed(self):
        baseline = {
            "name": "app", "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"direct": "1.0.0"}},
                "node_modules/direct": {"version": "1.0.0", "dependencies": {}},
            },
        }
        release = {
            "name": "app", "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"direct": "1.0.0"}},
                "node_modules/direct": {"version": "1.0.0", "dependencies": {"nested": "2.0.0"}},
                "node_modules/direct/node_modules/nested": {
                    "version": "2.0.0", "resolved": "https://registry.npmjs.org/nested/-/nested-2.0.0.tgz",
                    "integrity": "sha512-example",
                },
            },
        }
        changes = compare_npm_locks(json.dumps(baseline), json.dumps(release))
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["kind"], "transitive")
        self.assertEqual(changes[0]["chain"], ["direct", "nested"])

    def test_changed_transitive_without_integrity_is_high_severity(self):
        baseline = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"direct": "1"}},
                    "node_modules/direct": {"version": "1", "dependencies": {}}}}
        release = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"direct": "1"}},
                    "node_modules/direct": {"version": "1", "dependencies": {"nested": "2"}},
                    "node_modules/direct/node_modules/nested": {"version": "2", "resolved": "https://registry.npmjs.org/nested/-/nested-2.tgz"}}}
        patch = "diff --git a/package-lock.json b/package-lock.json\n--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1 @@\n-old\n+new\n"
        report = assess(patch, baseline_lock=json.dumps(baseline), release_lock=json.dumps(release))
        self.assertIn("Changed package has no integrity hash", [finding["title"] for finding in report["findings"]])
        self.assertEqual(report["decision"], "CANARY")

    def test_privacy_blast_radius_links_sink_to_transitive_dependency(self):
        baseline = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"checkout-telemetry": "1.0.0"}},
                "node_modules/checkout-telemetry": {
                    "version": "1.0.0", "dependencies": {"session-replay-runtime": "0.4.0"},
                },
                "node_modules/checkout-telemetry/node_modules/session-replay-runtime": {"version": "0.4.0"},
            },
        }
        release = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"checkout-telemetry": "1.1.0"}},
                "node_modules/checkout-telemetry": {
                    "version": "1.1.0", "dependencies": {"session-replay-runtime": "0.5.0"},
                },
                "node_modules/checkout-telemetry/node_modules/session-replay-runtime": {"version": "0.5.0"},
            },
        }
        patch = (
            "diff --git a/services/checkout.py b/services/checkout.py\n"
            "--- /dev/null\n+++ b/services/checkout.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+from checkout_telemetry import track\n"
            "+payload = {\"email\": customer.email}\n"
            "+track(\"checkout\", payload)\n"
        )
        report = assess(patch, baseline_lock=json.dumps(baseline), release_lock=json.dumps(release))
        radar = report["privacy_radar"]
        self.assertTrue(radar["release_gate"])
        self.assertEqual(radar["level"], "critical")
        self.assertEqual(radar["routes"][0]["dependency"]["name"], "checkout-telemetry")
        self.assertEqual(radar["routes"][0]["transitive"][0]["name"], "session-replay-runtime")
        self.assertEqual(report["decision"], "HOLD")

    def test_privacy_field_without_sink_stays_contained(self):
        patch = (
            "diff --git a/app.py b/app.py\n"
            "--- /dev/null\n+++ b/app.py\n"
            "@@ -0,0 +1 @@\n"
            "+payload = {\"email\": customer.email}\n"
        )
        radar = assess(patch)["privacy_radar"]
        self.assertEqual(radar["level"], "contained")
        self.assertFalse(radar["flows"])
        self.assertFalse(radar["release_gate"])


if __name__ == "__main__":
    unittest.main()
