#!/usr/bin/env python3
"""Scrape product documentation for RAG ingestion.
Outputs raw JSON files compatible with chunker.py.
"""
import json
import os
import glob
from pathlib import Path

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw_products')
os.makedirs(OUTPUT_DIR, exist_ok=True)

PRODUCTS = [
    {
        "name": "Monolith",
        "origin": "https://github.com/goodsun/monolith",
        "files": [
            ("~/tools/monolith/README.md", "README"),
            ("~/tools/monolith/docs/concept.md", "Concept"),
            ("~/tools/monolith/docs/learning-guide.md", "Learning Guide"),
        ]
    },
    {
        "name": "siegeNgin",
        "origin": "https://github.com/goodsun/siegeNgin",
        "files": [
            ("~/tools/siegeNgin/README.md", "README"),
            ("~/tools/siegeNgin/docs/CONCEPT.md", "Concept"),
            ("~/tools/siegeNgin/docs/ARCHITECTURE.md", "Architecture"),
            ("~/tools/siegeNgin/docs/WHY.md", "Why siegeNgin"),
            ("~/tools/siegeNgin/docs/whitepaper_ja.md", "Whitepaper (日本語)"),
        ]
    },
    {
        "name": "XPathGenie",
        "origin": "https://github.com/goodsun/XPathGenie",
        "files": [
            ("~/tools/XPathGenie/README.md", "README"),
            ("~/tools/XPathGenie/extension/README_JP.md", "XPathAbu — DomCatcher (日本語)"),
            ("~/tools/XPathGenie/extension/README.md", "XPathAbu — DomCatcher"),
            ("~/tools/XPathGenie/docs/DESIGN.md", "Design"),
            ("~/tools/XPathGenie/docs/whitepaper_jp.md", "Whitepaper (日本語)"),
        ]
    },
    {
        "name": "ChatBot Lite",
        "origin": "https://github.com/goodsun/chatbotlite",
        "files": [
            ("~/tools/chatbotlite/README.md", "README"),
        ]
    },
    {
        "name": "medical_open_data (MODS)",
        "origin": "https://github.com/goodsun/medical_open_data",
        "files": [
            ("~/tools/medical_open_data/README.md", "README"),
        ]
    },
]

def slugify(name):
    return name.lower().replace(" ", "_").replace("(", "").replace(")", "")

total = 0
for product in PRODUCTS:
    for filepath, doc_title in product["files"]:
        filepath = os.path.expanduser(filepath)
        if not os.path.exists(filepath):
            print(f"  SKIP (not found): {filepath}")
            continue

        with open(filepath, 'r', encoding='utf-8') as f:
            body = f.read().strip()

        if not body:
            print(f"  SKIP (empty): {filepath}")
            continue

        key = f"{slugify(product['name'])}_{slugify(doc_title)}"
        doc = {
            "key": key,
            "origin": product["origin"],
            "title": f"{product['name']} — {doc_title}",
            "date": "",
            "body": body,
            "tags": ", ".join([product["name"], doc_title, "bon-soleil", "product"]),
        }

        out_path = os.path.join(OUTPUT_DIR, f"{key}.json")
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        
        total += 1
        print(f"  OK: {product['name']} / {doc_title} ({len(body)} chars)")

print(f"\nDone: {total} documents -> {OUTPUT_DIR}")
