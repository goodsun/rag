#!/usr/bin/env python3
"""ragMyAdmin — ChromaDB Web Frontend"""
import os
import sys
import json
from flask import Flask, render_template, request, jsonify
import chromadb

CHROMA_PATH = os.environ.get("CHROMA_PATH", os.path.join(os.path.dirname(__file__), "..", "chroma_db"))


def meta_title(meta):
    """Extract document title from metadata with fallback."""
    if not meta:
        return ""
    return (meta.get("document_title") or meta.get("article_title")
            or meta.get("title") or meta.get("source") or "")


def meta_url(meta):
    """Extract source URL from metadata with fallback."""
    if not meta:
        return ""
    return (meta.get("origin_url") or meta.get("article_url")
            or meta.get("url") or meta.get("source_url") or "")


import re
from functools import lru_cache

def detect_field_roles(metadatas):
    """Auto-detect metadata field roles by analyzing values.
    
    Returns dict: {
        "title": "field_name" or None,
        "url": "field_name" or None,
        "date": "field_name" or None,
        "key": "field_name" or None,
        "index": "field_name" or None,
    }
    """
    if not metadatas:
        return {}
    
    # Collect all keys and sample values
    key_values = {}
    for m in metadatas:
        if not m:
            continue
        for k, v in m.items():
            if k not in key_values:
                key_values[k] = []
            key_values[k].append(v)
    
    roles = {"title": None, "url": None, "date": None, "key": None, "index": None}
    scored = {role: [] for role in roles}
    
    url_re = re.compile(r'^https?://')
    date_re = re.compile(r'^\d{4}-\d{2}-\d{2}')
    
    for key, values in key_values.items():
        sample = [v for v in values[:100] if v is not None]
        if not sample:
            continue
        
        str_samples = [str(v) for v in sample]
        key_lower = key.lower()
        
        # URL detection: values look like URLs
        url_ratio = sum(1 for s in str_samples if url_re.match(s)) / len(str_samples)
        if url_ratio > 0.8:
            score = url_ratio
            if "url" in key_lower or "uri" in key_lower or "link" in key_lower:
                score += 0.5
            if "origin" in key_lower or "source" in key_lower:
                score += 0.3
            scored["url"].append((key, score))
        
        # Date detection: ISO date pattern
        date_ratio = sum(1 for s in str_samples if date_re.match(s)) / len(str_samples)
        if date_ratio > 0.8:
            score = date_ratio
            if "date" in key_lower or "time" in key_lower or "publish" in key_lower or "created" in key_lower:
                score += 0.5
            scored["date"].append((key, score))
        
        # Title detection: string values, varied, not URLs, not dates
        if all(isinstance(v, str) for v in sample):
            if url_ratio < 0.1 and date_ratio < 0.1:
                unique_ratio = len(set(str_samples)) / len(str_samples)
                avg_len = sum(len(s) for s in str_samples) / len(str_samples)
                if avg_len > 3 and avg_len < 200:
                    score = 0.5
                    if "title" in key_lower or "name" in key_lower:
                        score += 1.0
                    if "doc" in key_lower or "article" in key_lower or "source" in key_lower:
                        score += 0.3
                    # Not fully unique = grouping field (good for title)
                    if 0.01 < unique_ratio < 0.95:
                        score += 0.3
                    scored["title"].append((key, score))
        
        # Key detection: string, used for grouping, fewer unique values than total
        if all(isinstance(v, str) for v in sample):
            unique_ratio = len(set(str_samples)) / len(str_samples)
            if 0.01 < unique_ratio < 0.95 and url_ratio < 0.1:
                score = 0.5
                if "key" in key_lower or "id" in key_lower or "doc" in key_lower:
                    score += 1.0
                if "article" in key_lower or "source" in key_lower:
                    score += 0.3
                # Shorter values are more likely to be keys
                avg_len = sum(len(s) for s in str_samples) / len(str_samples)
                if avg_len < 30:
                    score += 0.3
                scored["key"].append((key, score))
        
        # Index detection: integer-like, small values, sequential
        if all(isinstance(v, (int, float)) for v in sample):
            max_val = max(sample)
            if max_val < 1000:
                score = 0.5
                if "index" in key_lower or "seq" in key_lower or "num" in key_lower:
                    score += 1.0
                if "chunk" in key_lower:
                    score += 0.8
                # Penalize "total" or "count" fields — they're not indices
                if "total" in key_lower or "count" in key_lower:
                    score -= 1.0
                if score > 0:
                    scored["index"].append((key, score))
    
    # Pick highest scored field for each role
    for role in roles:
        if scored[role]:
            scored[role].sort(key=lambda x: -x[1])
            roles[role] = scored[role][0][0]
    
    return roles


# Cache per collection name
_field_roles_cache = {}

def get_field_roles(col_name):
    """Get or compute field roles for a collection."""
    if col_name not in _field_roles_cache:
        client = get_client()
        col = client.get_collection(col_name)
        sample = col.get(limit=200, include=["metadatas"])
        _field_roles_cache[col_name] = detect_field_roles(sample["metadatas"])
    return _field_roles_cache[col_name]


def smart_title(meta, roles):
    """Get title using detected role, with fallback."""
    if not meta:
        return ""
    if roles.get("title"):
        val = meta.get(roles["title"])
        if val:
            return str(val)
    return meta_title(meta)


def smart_url(meta, roles):
    """Get URL using detected role, with fallback."""
    if not meta:
        return ""
    if roles.get("url"):
        val = meta.get(roles["url"])
        if val:
            return str(val)
    return meta_url(meta)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["APPLICATION_ROOT"] = os.environ.get("APP_ROOT", "/")

# Support reverse proxy with subpath
class PrefixMiddleware:
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix.rstrip("/")
    def __call__(self, environ, start_response):
        if self.prefix:
            environ["SCRIPT_NAME"] = self.prefix
            path = environ.get("PATH_INFO", "")
            if path.startswith(self.prefix):
                environ["PATH_INFO"] = path[len(self.prefix):] or "/"
        return self.app(environ, start_response)


BASE = os.environ.get("APP_ROOT", "").rstrip("/")

def get_client():
    return chromadb.PersistentClient(path=CHROMA_PATH)

@app.context_processor
def inject_base():
    return {"BASE": BASE}


@app.route("/")
def index():
    client = get_client()
    collections = []
    for col in client.list_collections():
        collections.append({"name": col.name, "count": col.count()})
    return render_template("index.html", collections=collections)


@app.route("/collection/<name>")
def collection_view(name):
    client = get_client()
    col = client.get_collection(name)
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    
    # Get total count
    total = col.count()
    
    # Filter support
    filter_key = request.args.get("filter", "")
    
    # Get chunk IDs
    if filter_key:
        # Get all and filter by ID prefix
        all_result = col.get(include=["documents", "metadatas"])
        filtered_ids = [i for i, doc_id in enumerate(all_result["ids"]) if doc_id.startswith(filter_key)]
        total = len(filtered_ids)
        start = (page - 1) * per_page
        end = start + per_page
        page_indices = filtered_ids[start:end]
        result = {
            "ids": [all_result["ids"][i] for i in page_indices],
            "documents": [all_result["documents"][i] for i in page_indices],
            "metadatas": [all_result["metadatas"][i] for i in page_indices],
        }
    else:
        result = col.get(
            limit=per_page,
            offset=(page - 1) * per_page,
            include=["documents", "metadatas"]
        )
    
    roles = get_field_roles(name)
    
    chunks = []
    for i, doc_id in enumerate(result["ids"]):
        meta = result["metadatas"][i] if result["metadatas"] else {}
        chunks.append({
            "id": doc_id,
            "document": result["documents"][i][:200] if result["documents"][i] else "",
            "full_document": result["documents"][i] or "",
            "metadata": meta,
            "title": smart_title(meta, roles),
            "url": smart_url(meta, roles),
        })
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template("collection.html",
        name=name, chunks=chunks, total=total,
        page=page, per_page=per_page, total_pages=total_pages)


@app.route("/collection/<name>/chunk/<chunk_id>")
def chunk_detail(name, chunk_id):
    client = get_client()
    col = client.get_collection(name)
    result = col.get(ids=[chunk_id], include=["documents", "metadatas", "embeddings"])
    
    if not result["ids"]:
        return "Chunk not found", 404
    
    chunk = {
        "id": result["ids"][0],
        "document": result["documents"][0],
        "metadata": result["metadatas"][0] if result["metadatas"] else {},
        "embedding_dim": len(result["embeddings"][0]) if result["embeddings"] is not None and len(result["embeddings"]) > 0 else 0,
        "embedding_preview": list(result["embeddings"][0][:10]) if result["embeddings"] is not None and len(result["embeddings"]) > 0 else [],
    }
    
    return render_template("chunk_detail.html", name=name, chunk=chunk)


@app.route("/collection/<name>/documents")
def documents_view(name):
    client = get_client()
    col = client.get_collection(name)
    all_data = col.get(include=["documents", "metadatas"])
    
    roles = get_field_roles(name)
    
    # Group by document key (ID before _c)
    articles = {}
    for i, doc_id in enumerate(all_data["ids"]):
        parts = doc_id.rsplit("_c", 1)
        art_key = parts[0] if len(parts) == 2 else doc_id
        if art_key not in articles:
            meta = all_data["metadatas"][i] if all_data["metadatas"] else {}
            date_field = roles.get("date", "published_at")
            articles[art_key] = {
                "key": art_key,
                "title": smart_title(meta, roles) or art_key,
                "url": smart_url(meta, roles),
                "published_at": (meta or {}).get(date_field, ""),
                "chunks": [],
                "total_chars": 0,
            }
        doc_len = len(all_data["documents"][i]) if all_data["documents"][i] else 0
        articles[art_key]["chunks"].append(doc_id)
        articles[art_key]["total_chars"] += doc_len
    
    # Sort by published_at desc, then title
    sorted_articles = sorted(articles.values(), key=lambda a: a.get("published_at", ""), reverse=True)
    
    return render_template("documents.html", name=name, documents=sorted_articles, total=len(sorted_articles))


@app.route("/api/roles/<name>")
def api_roles(name):
    """Return auto-detected field roles for a collection."""
    roles = get_field_roles(name)
    return jsonify(roles)


@app.route("/api/search", methods=["POST"])
def api_search():
    data = request.json
    col_name = data.get("collection", "note_articles")
    query = data.get("query", "")
    n_results = int(data.get("n_results", 10))
    
    client = get_client()
    col = client.get_collection(col_name)
    
    results = col.query(
        query_texts=[query],
        n_results=n_results,
        include=["documents", "metadatas", "distances"]
    )
    
    items = []
    for i, doc_id in enumerate(results["ids"][0]):
        items.append({
            "id": doc_id,
            "document": results["documents"][0][i],
            "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
            "distance": round(results["distances"][0][i], 4) if results["distances"] else None,
        })
    
    return jsonify({"results": items, "query": query, "collection": col_name})


@app.route("/api/delete", methods=["POST"])
def api_delete():
    data = request.json
    col_name = data.get("collection")
    chunk_ids = data.get("ids", [])
    
    if not col_name or not chunk_ids:
        return jsonify({"error": "collection and ids required"}), 400
    
    client = get_client()
    col = client.get_collection(col_name)
    col.delete(ids=chunk_ids)
    
    return jsonify({"deleted": len(chunk_ids), "remaining": col.count()})


@app.route("/api/stats/<name>")
def api_stats(name):
    client = get_client()
    col = client.get_collection(name)
    count = col.count()
    
    # Get sample metadata to understand structure
    sample = col.get(limit=5, include=["metadatas"])
    meta_keys = set()
    for m in (sample["metadatas"] or []):
        if m:
            meta_keys.update(m.keys())
    
    # Get source distribution and doc length stats
    all_data = col.get(include=["metadatas", "documents"])
    sources = {}
    doc_lengths = []
    roles = get_field_roles(name)
    for i, m in enumerate(all_data["metadatas"] or []):
        if m:
            src = smart_title(m, roles) or "unknown"
            sources[src] = sources.get(src, 0) + 1
        if all_data["documents"] and all_data["documents"][i]:
            doc_lengths.append(len(all_data["documents"][i]))
    
    len_stats = {}
    if doc_lengths:
        doc_lengths.sort()
        len_stats = {
            "min": min(doc_lengths),
            "max": max(doc_lengths),
            "avg": round(sum(doc_lengths) / len(doc_lengths)),
            "median": doc_lengths[len(doc_lengths) // 2],
            "total_chars": sum(doc_lengths),
        }
    
    return jsonify({
        "name": name,
        "count": count,
        "metadata_keys": sorted(meta_keys),
        "sources": dict(sorted(sources.items(), key=lambda x: -x[1])[:30]),
        "doc_lengths": len_stats,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8792))
    prefix = os.environ.get("APP_ROOT", "")
    if prefix:
        app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=prefix)
    app.run(host="0.0.0.0", port=port, debug=False)
