#!/usr/bin/env python3
"""Stage a small, explicit public documentation site for GitHub Pages.

The source documents remain in docs/ and results/. Only the paths selected here
are copied to the build directory. Other repository files are linked to their
GitHub source instead of being published as site assets.
"""

from __future__ import annotations

import argparse
import posixpath
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[([^\]]+)\]\((<[^>]+>|[^\s)]+)(\s+[^)]*)?\)")
IMAGE = re.compile(r"!\[([^\]]*)\]\((<[^>]+>|[^\s)]+)(\s+[^)]*)?\)")
CGNAT_ADDRESS = re.compile(rb"\b100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b")
# A generated GitHub source link is pinned to the exact commit being built so the published
# documentation and the code/JSON it points at stay the same snapshot. Local staging falls
# back to the literal branch "main"; CI passes the build commit (see --ref).
COMMIT_SHA = re.compile(r"^[0-9a-f]{7,40}$")
DEFAULT_REF = "main"


def validate_ref(ref: str) -> str:
    """Accept only a lowercase-hex commit SHA or the literal default branch.

    This keeps an arbitrary, unvalidated string from being interpolated into the generated
    GitHub URLs; a supplied ref must be a real commit SHA.
    """
    if ref == DEFAULT_REF or COMMIT_SHA.fullmatch(ref):
        return ref
    raise ValueError(f"ref must be a commit SHA (lowercase hex, 7-40 chars) or {DEFAULT_REF!r}: {ref!r}")


def selected_sources(root: Path) -> dict[Path, Path]:
    """Map staged paths to their source; never stage arbitrary repo contents."""
    paths: dict[Path, Path] = {
        Path("index.md"): Path("site/index.md"),
        Path("_config.yml"): Path("site/_config.yml"),
        Path("_layouts/default.html"): Path("site/_layouts/default.html"),
        Path("assets/site.css"): Path("site/assets/site.css"),
        Path("docs/index.md"): Path("docs/README.md"),
        Path("docs/README.md"): Path("docs/README.md"),
        Path("results/index.md"): Path("results/README.md"),
        Path("docs/assets/social-preview.png"): Path("docs/assets/social-preview.png"),
    }
    for source in sorted((root / "docs").glob("*.md")):
        if source.name != "README.md":
            rel = source.relative_to(root)
            paths[rel] = rel
    for source in sorted((root / "results").glob("*.md")):
        rel = source.relative_to(root)
        paths[rel] = rel
    for source in sorted((root / "results/model_demo").glob("*.md")):
        rel = source.relative_to(root)
        paths[rel] = rel
    for name in ("visual_report.html", "decision_distribution.svg"):
        rel = Path("results/model_demo") / name
        paths[rel] = rel
    for date in ("manual_replication_20261019", "manual_replication_20261022"):
        folder = Path("results/model_demo") / date
        for name in ("README.md", "visual_report.html", "decision_distribution.svg"):
            rel = folder / name
            paths[rel] = rel
    return paths


def rewrite_url(raw: str, source: Path, output: Path, staged: set[Path], root: Path, ref: str = DEFAULT_REF) -> str:
    url = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
    split = urlsplit(url)
    if split.scheme or split.netloc or not split.path:
        return raw
    if split.path.startswith("/"):
        raise ValueError(f"{source}: root-relative link is not portable: {url}")
    decoded = unquote(split.path)
    if "\\" in decoded:
        raise ValueError(f"{source}: backslash in link: {url}")
    site_target = Path(posixpath.normpath(str(output.parent / decoded)))
    source_target = Path(posixpath.normpath(str(source.parent / decoded)))
    if site_target.is_absolute() or source_target.is_absolute() or ".." in source_target.parts:
        raise ValueError(f"{source}: link escapes repository: {url}")
    if decoded.endswith("/") and site_target / "index.md" in staged:
        return raw
    if site_target in staged:
        # Point internal links at the rendered .html so they resolve without the GitHub-Pages-only
        # jekyll-relative-links plugin (and so a plain Jekyll build works too).
        if site_target.suffix == ".md" and split.path.endswith(".md"):
            html_path = split.path[: -len(".md")] + ".html"
            return urlunsplit(("", "", html_path, split.query, split.fragment))
        return raw
    if source_target not in staged and (root / source_target).is_file():
        kind = "blob"
        target = source_target
    elif source_target not in staged and (root / source_target).is_dir():
        kind = "tree"
        target = source_target
    else:
        raise ValueError(f"{source}: missing relative link: {url}")
    github_path = f"/kyitharko/aisig-proto/{kind}/{ref}/{quote(target.as_posix(), safe='/')}"
    return urlunsplit(("https", "github.com", github_path, split.query, split.fragment))


def split_front_matter(text: str) -> tuple[str | None, str]:
    """Return (front_matter_block_or_None, body)."""
    if text.startswith(("---\n", "---\r\n")):
        lines = text.split("\n")
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                return "\n".join(lines[: i + 1]) + "\n", "\n".join(lines[i + 1 :])
    return None, text


def prepare_markdown(text: str) -> str:
    """Make a Markdown page self-contained for any Jekyll build (no GitHub-Pages-only plugins).

    Adds YAML front matter (so plain Jekyll renders it to HTML with the site layout; the title
    comes from the first H1) and wraps the body in a Liquid ``{% raw %}`` block so documentation
    that happens to contain ``{{ ... }}`` or ``{% ... %}`` (e.g. a ``docker inspect`` format
    string) is published verbatim instead of being interpreted as a template.
    """
    fm, body = split_front_matter(text)
    if fm is None:
        title = None
        for line in body.splitlines():
            m = re.match(r"^#\s+(.+?)\s*#*\s*$", line)
            if m:
                title = m.group(1).replace("`", "").strip()
                break
        if title:
            safe = title.replace("\\", "\\\\").replace('"', '\\"')
            fm = f'---\ntitle: "{safe}"\n---\n'
        else:
            fm = "---\n---\n"
    return f"{fm}{{% raw %}}\n{body.lstrip(chr(10))}\n{{% endraw %}}\n"


def rewrite_markdown(text: str, source: Path, output: Path, staged: set[Path], root: Path, ref: str = DEFAULT_REF) -> str:
    # Fenced code is copied literally. All ordinary relative links must resolve.
    lines: list[str] = []
    fence: str | None = None
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append(line)
            continue
        if fence is not None:
            lines.append(line)
            continue
        def replace(m: re.Match[str], prefix: str) -> str:
            new = rewrite_url(m.group(2), source, output, staged, root, ref)
            return f"{prefix}[{m.group(1)}]({new}{m.group(3) or ''})"
        line = IMAGE.sub(lambda m: replace(m, "!"), line)
        line = LINK.sub(lambda m: replace(m, ""), line)
        lines.append(line)
    return "".join(lines)


def build(root: Path, destination: Path, ref: str = DEFAULT_REF) -> list[Path]:
    ref = validate_ref(ref)
    root = root.resolve()
    destination = destination.resolve()
    protected = (root / "docs", root / "results", root / "site")
    if destination == root or any(destination == path or path in destination.parents for path in protected):
        raise ValueError("output must not replace source documents")
    if destination.exists():
        raise ValueError(f"output already exists: {destination}")
    paths = selected_sources(root)
    missing = [str(source) for source in paths.values() if not (root / source).is_file()]
    if missing:
        raise ValueError(f"missing source files: {', '.join(missing)}")
    staged = set(paths)
    # Resolve links before writing anything, so failures never leave a partial site.
    content: dict[Path, bytes] = {}
    for output, source in paths.items():
        body = (root / source).read_bytes()
        if output.suffix == ".md":
            rendered = rewrite_markdown(body.decode("utf-8"), source, output, staged, root, ref)
            body = prepare_markdown(rendered).encode("utf-8")
        content[output] = body
    if any(CGNAT_ADDRESS.search(body) or b"resumeToken" in body for body in content.values()):
        raise ValueError("a private address or export token marker would be published")
    for output, body in content.items():
        target = destination / output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return sorted(paths)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory for Jekyll sources")
    parser.add_argument(
        "--ref",
        default=DEFAULT_REF,
        help="commit SHA to pin generated GitHub source links to (CI passes the build commit; "
        f"local builds default to {DEFAULT_REF!r})",
    )
    args = parser.parse_args()
    paths = build(ROOT, args.output, args.ref)
    print(f"Staged {len(paths)} allowlisted files at {args.output} (source links pinned to {args.ref}); "
          "no raw JSON or source code.")


if __name__ == "__main__":
    main()
