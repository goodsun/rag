#!/usr/bin/env python3
"""Scrape arXiv papers (HTML version) for RAG ingestion.

Usage:
    python3 scrape_arxiv.py 2501.00226 2503.06138 ...
    python3 scrape_arxiv.py --list papers.txt

Output: data/raw_papers/<arxiv_id>.json
"""
from __future__ import annotations
import sys, os, json, re, time, requests
from pathlib import Path

RAW_DIR = Path(os.environ.get("RAW_DIR", "data/raw_papers"))

def fetch_paper(arxiv_id: str) -> dict | None:
    """Fetch paper metadata from abs page + full text from HTML version."""
    # Get abstract + metadata from abs page
    abs_url = f"https://arxiv.org/abs/{arxiv_id}"
    r = requests.get(abs_url, timeout=30)
    if r.status_code != 200:
        print(f"  ✗ abs page failed: {r.status_code}")
        return None

    text = r.text

    # Extract title
    m = re.search(r'<meta name="citation_title" content="([^"]+)"', text)
    title = m.group(1) if m else "Unknown"

    # Extract authors
    authors = re.findall(r'<meta name="citation_author" content="([^"]+)"', text)

    # Extract date
    m = re.search(r'<meta name="citation_date" content="([^"]+)"', text)
    date = m.group(1) if m else ""

    # Extract abstract
    m = re.search(r'<meta name="citation_abstract" content="([^"]*)"', text, re.DOTALL)
    abstract = m.group(1).strip() if m else ""

    # Try HTML version for full text
    html_url = f"https://arxiv.org/html/{arxiv_id}"
    # Try with version suffix
    m_ver = re.search(rf'href="(/html/{re.escape(arxiv_id)}v\d+)"', text)
    if m_ver:
        html_url = f"https://arxiv.org{m_ver.group(1)}"

    full_text = ""
    r2 = requests.get(html_url, timeout=60)
    if r2.status_code == 200:
        # Extract article body, strip HTML tags
        body = r2.text
        # Remove script/style
        body = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', body, flags=re.DOTALL)
        # Try to get just the article content
        m_article = re.search(r'<article[^>]*>(.*?)</article>', body, re.DOTALL)
        if m_article:
            body = m_article.group(1)
        # Remove references section (often very long)
        body = re.split(r'<(?:section|div)[^>]*(?:id|class)="[^"]*(?:bib|references)[^"]*"', body)[0]
        # Convert headers to markdown-style
        body = re.sub(r'<h([1-6])[^>]*>(.*?)</h\1>', lambda m: '#' * int(m.group(1)) + ' ' + m.group(2), body)
        # Convert <p> to newlines
        body = re.sub(r'</?p[^>]*>', '\n', body)
        # Remove remaining HTML tags
        body = re.sub(r'<[^>]+>', ' ', body)
        # Clean up whitespace
        body = re.sub(r'[ \t]+', ' ', body)
        body = re.sub(r'\n\s*\n', '\n\n', body)
        full_text = body.strip()
    else:
        print(f"  ⚠ HTML version not available ({r2.status_code}), using abstract only")
        full_text = abstract

    return {
        "arxiv_id": arxiv_id,
        "title": title,
        "authors": authors,
        "date": date,
        "abstract": abstract,
        "origin": "https://arxiv.org/abs/",
        "key": arxiv_id,
        "body": full_text
    }


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 scrape_arxiv.py <arxiv_id> [arxiv_id ...]")
        print("       python3 scrape_arxiv.py --list papers.txt")
        sys.exit(1)

    if args[0] == "--list":
        with open(args[1]) as f:
            ids = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        ids = args

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    for arxiv_id in ids:
        print(f"Fetching {arxiv_id}...")
        paper = fetch_paper(arxiv_id)
        if paper:
            out = RAW_DIR / f"{arxiv_id.replace('/', '_')}.json"
            with open(out, "w") as f:
                json.dump(paper, f, ensure_ascii=False, indent=2)
            print(f"  ✓ {paper['title'][:60]}... ({len(paper['body'])} chars)")
        time.sleep(2)  # Be polite

    print(f"\nDone! {len(ids)} papers → {RAW_DIR}/")


if __name__ == "__main__":
    main()
