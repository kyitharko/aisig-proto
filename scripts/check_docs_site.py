#!/usr/bin/env python3
"""Check rendered GitHub Pages links after Jekyll has built the staged site."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

BASEURL = "/aisig-proto"


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attribute = {"a": "href", "link": "href", "img": "src", "script": "src"}.get(tag)
        if attribute:
            self.urls.extend(v for k, v in attrs if k == attribute and v)


def problems(site: Path) -> list[str]:
    site = site.resolve()
    errors: list[str] = []
    for pattern in ("*.json", "*.key", "*.pem"):
        errors.extend(f"unexpected published file: {p.relative_to(site)}" for p in site.rglob(pattern))
    for name in ("src", "tests", "demo", "local-experiments"):
        if (site / name).exists():
            errors.append(f"unexpected published directory: {name}")
    required = (
        "index.html", "docs/index.html", "docs/spec.html", "docs/rq123.html",
        "docs/threat-model.html", "results/index.html",
        "results/model_demo/manual_replication_20261022/visual_report.html",
        "assets/site.css",
    )
    for name in required:
        if not (site / name).is_file():
            errors.append(f"missing page: {name}")
    for page in sorted(site.rglob("*.html")):
        parser = Links()
        parser.feed(page.read_text(encoding="utf-8"))
        for raw in parser.urls:
            parsed = urlsplit(raw)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            decoded = unquote(parsed.path)
            if decoded.startswith("/"):
                if not decoded.startswith(BASEURL + "/"):
                    errors.append(f"{page.relative_to(site)}: link outside project base URL: {raw}")
                    continue
                target = site / decoded[len(BASEURL) + 1 :]
            else:
                target = page.parent / decoded
            target = target.resolve()
            if site not in target.parents and target != site:
                errors.append(f"{page.relative_to(site)}: link escapes site: {raw}")
                continue
            if target.is_dir():
                target = target / "index.html"
            if not target.is_file():
                errors.append(f"{page.relative_to(site)}: unresolved link: {raw}")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path)
    args = parser.parse_args()
    errors = problems(args.site)
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Rendered site links OK: {args.site}")


if __name__ == "__main__":
    main()
