#!/usr/bin/env python3
"""ragMyAdmin — ChromaDB Web Frontend"""
import os
import sys
import json
from flask import Flask, render_template, request, jsonify
import chromadb

CHROMA_PATH = os.environ.get("CHROMA_PATH", os.path.join(os.path.dirname(__file__), "..", "chroma_db"))

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
    
    # Get chunk IDs
    result = col.get(
        limit=per_page,
        offset=(page - 1) * per_page,
        include=["documents", "metadatas"]
    )
    
    chunks = []
    for i, doc_id in enumerate(result["ids"]):
        chunks.append({
            "id": doc_id,
            "document": result["documents"][i][:200] if result["documents"][i] else "",
            "full_document": result["documents"][i] or "",
            "metadata": result["metadatas"][i] if result["metadatas"] else {},
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
    key = "article_title" if "article_title" in meta_keys else "title" if "title" in meta_keys else "source"
    for i, m in enumerate(all_data["metadatas"] or []):
        if m:
            src = m.get(key, "unknown")
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
