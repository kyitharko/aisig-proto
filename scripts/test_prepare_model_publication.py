#!/usr/bin/env python3
"""Offline checks for creating a publication candidate from a completed model run."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_model_publication as pub


class PublicationTests(unittest.TestCase):
    def setUp(self):
        pub.LOCAL.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="publication-test-", dir=pub.LOCAL)
        self.base = Path(self.tmp.name)
        self.old_results = pub.RESULTS
        pub.RESULTS = self.base / "results/model_demo"
        pub.RESULTS.mkdir(parents=True)
        self.raw = self.base / "full-20261022T105748Z-668695e4"
        self.raw.mkdir()
        reference = pub.ROOT / "results/model_demo/manual_replication_20261019"
        for name in ("controls_results.json", "model_matrix.json"):
            (self.raw / name).write_bytes((reference / name).read_bytes())
        controls = self.load("controls_results.json")
        controls["controller_url"] = "http://100.64.1.2:8787"
        self.save("controls_results.json", controls)
        self.save("run_manifest.json", {
            "mode": "full", "collector_returncode": 0,
            "output_directory": str(self.raw.relative_to(pub.ROOT)),
            "started_utc": "2026-10-22T10:57:48+00:00",
            "ended_utc": "2026-10-22T11:03:00+00:00", "git_commit": "a" * 40,
        })
        self.candidate = self.base / "publication-candidate"

    def tearDown(self):
        pub.RESULTS = self.old_results
        self.tmp.cleanup()

    def load(self, name):
        return json.loads((self.raw / name).read_text())

    def save(self, name, data):
        (self.raw / name).write_bytes(pub.json_bytes(data))

    def test_complete_candidate_preserves_original_and_reproduces_visuals(self):
        original = {p.name: p.read_bytes() for p in self.raw.iterdir()}
        pub.prepare(self.raw, self.candidate)
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.raw.iterdir()})
        self.assertEqual(set(pub.FILES), {p.name for p in self.candidate.iterdir()})
        counts = pub.check_dir(self.candidate)
        self.assertEqual(dict(counts), {"Allow": 4, "Deny": 17,
                                        "Indeterminate": 8, "No mediation": 1})
        self.assertNotIn("100.64.1.2", (self.candidate / "controls_results.json").read_text())
        with self.assertRaises(pub.PublicationError):
            pub.prepare(self.raw, self.candidate)  # never overwrite a reviewed candidate

    def test_failed_manifest_cannot_be_published(self):
        manifest = self.load("run_manifest.json")
        manifest["collector_returncode"] = 1
        self.save("run_manifest.json", manifest)
        with self.assertRaisesRegex(pub.PublicationError, "successful full run"):
            pub.prepare(self.raw, self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_preregistered_control_drift_is_rejected(self):
        controls = self.load("controls_results.json")
        controls["controls"][0]["expected_decision"] = "invented decision"
        self.save("controls_results.json", controls)
        with self.assertRaisesRegex(pub.PublicationError, "drift"):
            pub.prepare(self.raw, self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_workflow_hash_drift_is_rejected(self):
        matrix = self.load("model_matrix.json")
        matrix["runs"][0]["committed_variant_sha256"] = "0" * 64
        self.save("model_matrix.json", matrix)
        with self.assertRaisesRegex(pub.PublicationError, "hash mismatch"):
            pub.prepare(self.raw, self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_sensitive_key_removed_and_unknown_address_refused(self):
        matrix = self.load("model_matrix.json")
        matrix["runs"][0]["model_raw_message"]["resumeToken"] = "never-print-me"
        self.save("model_matrix.json", matrix)
        pub.prepare(self.raw, self.candidate)
        self.assertNotIn("resumeToken", (self.candidate / "model_matrix.json").read_text())
        self.assertIn("resumeToken", (self.raw / "model_matrix.json").read_text())
        self.candidate.rename(self.base / "previous-candidate")
        matrix["runs"][0]["model_raw_message"]["content"] = "address 10.0.0.1"
        self.save("model_matrix.json", matrix)
        with self.assertRaisesRegex(pub.PublicationError, "IPv4 address"):
            pub.prepare(self.raw, self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_tampered_visual_or_readme_fails_recheck(self):
        pub.prepare(self.raw, self.candidate)
        html = self.candidate / "visual_report.html"
        html.write_text(html.read_text() + "edited")
        with self.assertRaisesRegex(pub.PublicationError, "HTML does not match"):
            pub.check_dir(self.candidate)
        html.write_text(html.read_text().removesuffix("edited"))
        note = self.candidate / "README.md"
        note.write_text("no source hashes")
        with self.assertRaisesRegex(pub.PublicationError, "README does not match"):
            pub.check_dir(self.candidate)

    def test_raw_model_call_cannot_be_relabelled_in_published_proposal(self):
        matrix = self.load("model_matrix.json")
        row = next(r for r in matrix["runs"] if r["model_parse"] == "tool_call")
        row["proposal"]["target"] = "web:https://app.acme.test:443/app/admin"
        self.save("model_matrix.json", matrix)
        with self.assertRaisesRegex(pub.PublicationError, "raw/recorded classifier target mismatch"):
            pub.prepare(self.raw, self.candidate)
        self.assertFalse(self.candidate.exists())

    def test_manifest_or_narrative_drift_is_rejected(self):
        pub.prepare(self.raw, self.candidate)
        summary = self.candidate / "publication_manifest.json"
        metadata = json.loads(summary.read_text())
        metadata["git_commit"] = "not a hash"
        summary.write_bytes(pub.json_bytes(metadata))
        with self.assertRaisesRegex(pub.PublicationError, "invalid Git commit"):
            pub.check_dir(self.candidate)

    def test_unexpected_file_in_candidate_is_rejected(self):
        pub.prepare(self.raw, self.candidate)
        (self.candidate / "raw-export.json").write_text("{}")
        with self.assertRaisesRegex(pub.PublicationError, "exactly the six"):
            pub.check_dir(self.candidate)

    def test_promotion_preserves_recorded_evidence_and_rechecks_narrative(self):
        pub.prepare(self.raw, self.candidate)
        output = pub.RESULTS / "publication-test-only"
        self.assertFalse(output.exists())
        pub.promote(self.candidate, output)
        self.assertEqual(pub.check_dir(output), pub.check_dir(self.candidate))
        for name in ("controls_results.json", "model_matrix.json",
                     "visual_report.html", "decision_distribution.svg"):
            self.assertEqual((self.candidate / name).read_bytes(),
                             (output / name).read_bytes(), name)
        self.assertIn("publication copy", (output / "README.md").read_text())
        self.assertNotIn("Review this candidate before moving",
                         (output / "README.md").read_text())
        with self.assertRaises(pub.PublicationError):
            pub.promote(self.candidate, output)

    def test_tampered_candidate_cannot_be_promoted(self):
        pub.prepare(self.raw, self.candidate)
        (self.candidate / "README.md").write_text("tampered narrative")
        output = pub.RESULTS / "publication-test-only"
        with self.assertRaisesRegex(pub.PublicationError, "README does not match"):
            pub.promote(self.candidate, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
