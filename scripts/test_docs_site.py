#!/usr/bin/env python3
"""Offline unit and staging checks for the public docs build."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from build_docs_site import CGNAT_ADDRESS, ROOT, build, rewrite_markdown, rewrite_url, selected_sources
from check_docs_site import problems


class DocsSiteTests(unittest.TestCase):
    def test_stage_current_repository_and_keep_raw_files_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "site"
            paths = build(ROOT, target)
            self.assertIn(Path("docs/index.md"), paths)
            self.assertIn(Path("results/model_demo/manual_replication_20261022/visual_report.html"), paths)
            self.assertFalse(list(target.rglob("*.json")))
            self.assertFalse((target / "src").exists())
            self.assertFalse((target / "demo").exists())
            self.assertIn(
                "https://github.com/kyitharko/aisig-proto/blob/main/demo/compose.cpu.yml",
                (target / "docs/remote-manual-access.md").read_text(),
            )
            # Internal .md links are rewritten to the rendered .html so the site works without
            # the GitHub-Pages-only jekyll-relative-links plugin.
            self.assertIn(
                "[session slice](session.html)",
                (target / "docs/index.md").read_text(),
            )

    def test_missing_link_fails_before_output_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "doc.md"
            source.write_text("See [gone](missing.md).")
            with self.assertRaisesRegex(ValueError, "missing relative link"):
                rewrite_markdown(source.read_text(), Path("doc.md"), Path("doc.md"), set(), Path(tmp))

    def test_relative_link_to_code_becomes_github_source_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "demo").mkdir()
            (root / "demo/example.json").write_text("{}")
            url = rewrite_url("../demo/example.json#sample", Path("docs/page.md"), Path("docs/page.md"), set(), root)
            self.assertEqual(url, "https://github.com/kyitharko/aisig-proto/blob/main/demo/example.json#sample")

    def test_external_source_link_is_pinned_to_supplied_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "demo").mkdir()
            (root / "demo/example.json").write_text("{}")
            sha = "0123456789abcdef0123456789abcdef01234567"
            # Query string, fragment and percent-encoding survive; the mutable branch is replaced
            # by the exact build commit.
            url = rewrite_url(
                "../demo/example.json?plain=1#L3%20L4", Path("docs/page.md"), Path("docs/page.md"), set(), root, sha
            )
            self.assertEqual(
                url, f"https://github.com/kyitharko/aisig-proto/blob/{sha}/demo/example.json?plain=1#L3%20L4"
            )
            self.assertNotIn("/blob/main/", url)

    def test_internal_doc_link_stays_a_site_link_even_when_pinned(self) -> None:
        # An internal documentation link must remain a relative site link; the commit pin only
        # affects links that leave the website to repository source.
        url = rewrite_url(
            "session.md#slice", Path("docs/index.md"), Path("docs/index.md"), {Path("docs/session.md")},
            Path("."), "0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(url, "session.html#slice")
        self.assertNotIn("github.com", url)

    def test_invalid_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "commit SHA"):
                build(ROOT, Path(tmp) / "site", "feature/not-a-sha; rm -rf /")

    def test_escaping_link_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "escapes repository"):
                rewrite_url("../../../private.txt", Path("docs/page.md"), Path("docs/page.md"), set(), Path(tmp))

    def test_fenced_example_is_not_rewritten(self) -> None:
        text = "```md\n[example](missing.md)\n```\n"
        self.assertEqual(rewrite_markdown(text, Path("docs/page.md"), Path("docs/page.md"), set(), Path(".")), text)

    def test_rendered_link_checker_catches_broken_project_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            site = Path(tmp)
            (site / "index.html").write_text('<a href="/aisig-proto/docs/missing.html">broken</a>')
            self.assertTrue(any("unresolved" in e for e in problems(site)))

    def test_static_selection_is_narrow(self) -> None:
        paths = selected_sources(ROOT)
        self.assertFalse(any(".json" in str(p) or str(p).startswith("src/") for p in paths))

    def test_private_network_address_filter(self) -> None:
        self.assertTrue(CGNAT_ADDRESS.search(b"at 100.90.1.2:8787"))
        self.assertFalse(CGNAT_ADDRESS.search(b"the placeholder 100.x.y.z is fine"))


if __name__ == "__main__":
    unittest.main()
