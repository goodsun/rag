#!/usr/bin/env python3
"""ragMyAdmin — ChromaDB Web Frontend with Permission System"""
import os
import sys
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
import chromadb

# Import authentication module
from auth import (
    require_auth, require_role, phase1_policy, 
    check_rate_limit, log_login_attempt, verify_password, 
    get_client_ip, get_user_info, LOCKOUT_MINUTES
)

CHROMA_PATH = os.environ.get("CHROMA_PATH", os.path.join(os.path.dirname(__file__), "..", "chroma_db"))
EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

# Lazy-loaded embedding function
_embed_fn = None

def get_embed_fn():
    global _embed_fn
    if _embed_fn is None:
        from fastembed import TextEmbedding
        class FastEmbedFunction(chromadb.EmbeddingFunction):
            def __init__(self, model_name):
                self.model = TextEmbedding(model_name)
            def __call__(self, input):
                return [e.tolist() for e in self.model.embed(input)]
        _embed_fn = FastEmbedFunction(EMBEDDING_MODEL)
    return _embed_fn

def get_collection(name):
    """Get collection with embedding function for write operations."""
    client = get_client()
    return client.get_collection(name, embedding_function=get_embed_fn())

def meta_title(meta):
    """Extract document title from metadata with fallback."""
    if not meta:
        return ""
    return (meta.get("title") or meta.get("__title") or meta.get("document_title")
            or meta.get("article_title") or meta.get("source") or "")

def meta_url(meta):
    """Extract source URL from metadata with fallback. Reconstructs from origin + key if needed."""
    if not meta:
        return ""
    # origin + key で再構成
    origin = meta.get("origin", "")
    key = meta.get("key", "")
    if origin and key:
        return origin + key
    return (meta.get("url") or meta.get("__url") or meta.get("origin_url")
            or meta.get("article_url") or meta.get("source_url") or "")

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
    
    # Standard field names take priority (ragMyAdmin convention)
    standard_map = {
        "title": "title",
        "url": None,  # URL is reconstructed from origin + key
        "date": "date",
        "key": "key",
        "index": "index",
    }
    for role, std_key in standard_map.items():
        if std_key and std_key in key_values:
            roles[role] = std_key
        elif scored[role]:
            scored[role].sort(key=lambda x: -x[1])
            roles[role] = scored[role][0][0]
    
    # URL role: check for origin field (reconstruct from origin + key)
    if "origin" in key_values:
        roles["origin"] = "origin"
    
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
    """Get URL using detected role, with fallback. Always tries origin+key reconstruction first."""
    if not meta:
        return ""
    # origin + key reconstruction takes priority (most reliable)
    origin = meta.get("origin") or meta.get("__origin", "")
    key = meta.get("key") or meta.get("__key", "")
    if origin and key:
        return origin + key
    if roles.get("url"):
        val = meta.get(roles["url"])
        if val:
            return str(val)
    return meta_url(meta)

app = Flask(__name__)

# Security configuration
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
app.config["APPLICATION_ROOT"] = os.environ.get("APP_ROOT", "/")

# Flask-Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'sessions')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS via Apache
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_NAME'] = 'ragmyadmin_session'

# CSRF Protection
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
csrf = CSRFProtect(app)

# Initialize Flask-Session
Session(app)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# Phase 1 policy enforcement
@app.before_request
def enforce_security_policies():
    # Skip auth for login page and static files
    if request.endpoint in ['login', 'static']:
        return
    
    # Apply Phase 1 policy
    if 'username' in session:
        phase1_policy()

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
    return {
        "BASE": BASE,
        "user_info": get_user_info(session.get('username')) if 'username' in session else None
    }

# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        client_ip = get_client_ip()
        
        if not username or not password:
            return render_template('login.html', error='ユーザー名とパスワードを入力してください')
        
        # Check rate limiting
        if not check_rate_limit(username, client_ip):
            log_login_attempt(username, client_ip, success=False)
            return render_template('login.html', 
                error=f'ログイン試行回数が上限に達しました。{LOCKOUT_MINUTES}分後に再試行してください。',
                username=username)
        
        # Verify credentials
        user = verify_password(username, password)
        if user:
            # Successful login
            log_login_attempt(username, client_ip, success=True)
            
            # Clear old session and create new one
            session.clear()
            session['username'] = user['username']
            session['role'] = user['role']
            session['groups'] = user['groups']
            session['session_version'] = user['session_version']
            session.permanent = True
            
            return redirect(url_for('index'))
        else:
            # Failed login
            log_login_attempt(username, client_ip, success=False)
            return render_template('login.html', 
                error='ユーザー名またはパスワードが正しくありません',
                username=username)
    
    return render_template('login.html')

@app.route("/logout")
@require_auth
def logout():
    session.clear()
    return redirect(url_for('login'))

# Main routes with authentication
@app.route("/")
@require_auth
def index():
    client = get_client()
    collections = []
    for col in client.list_collections():
        count = col.count()
        # Count unique documents (by key or __key metadata)
        doc_count = 0
        if count > 0:
            try:
                all_meta = col.get(include=["metadatas"])["metadatas"]
                keys = set()
                for m in all_meta:
                    k = (m or {}).get("key") or (m or {}).get("__key") or ""
                    if k:
                        keys.add(k)
                doc_count = len(keys) if keys else count
            except Exception:
                doc_count = count
        collections.append({"name": col.name, "count": count, "doc_count": doc_count})
    return render_template("index.html", collections=collections)

@app.route("/collection/<name>")
@require_auth
def collection_view(name):
    """Show document list for a collection (was /collection/<name>/documents)."""
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
            date_field = roles.get("date") or "date"
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
    
    sorted_articles = sorted(articles.values(), key=lambda a: a.get("published_at", ""), reverse=True)
    
    return render_template("documents.html", current_collection=name, current_view="documents",
        name=name, documents=sorted_articles, total=len(sorted_articles), chunk_total=len(all_data["ids"]))

@app.route("/collection/<name>/document/<doc_key>")
@require_auth
def document_chunks_view(name, doc_key):
    """Show chunks belonging to a specific document."""
    client = get_client()
    col = client.get_collection(name)
    all_result = col.get(include=["documents", "metadatas"])
    
    roles = get_field_roles(name)
    
    # Filter chunks belonging to this document
    chunks = []
    doc_title = doc_key
    for i, doc_id in enumerate(all_result["ids"]):
        parts = doc_id.rsplit("_c", 1)
        art_key = parts[0] if len(parts) == 2 else doc_id
        if art_key == doc_key:
            meta = all_result["metadatas"][i] if all_result["metadatas"] else {}
            if not chunks:
                doc_title = smart_title(meta, roles) or doc_key
            chunks.append({
                "id": doc_id,
                "document": all_result["documents"][i][:200] if all_result["documents"][i] else "",
                "full_document": all_result["documents"][i] or "",
                "metadata": meta,
                "title": smart_title(meta, roles),
                "url": smart_url(meta, roles),
                "chunk_index": parts[1] if len(parts) == 2 else "",
            })
    
    # Sort by chunk index
    chunks.sort(key=lambda c: c.get("chunk_index", ""))
    
    return render_template("collection.html", current_collection=name, current_view="doc_chunks",
        name=name, doc_key=doc_key, doc_title=doc_title, chunks=chunks, total=len(chunks))

@app.route("/collection/<name>/chunk/<chunk_id>")
@require_auth
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
    
    return render_template("chunk_detail.html", current_collection=name, current_view="chunk_detail", name=name, chunk=chunk)

@app.route("/collection/<name>/documents")
@require_auth
def documents_view(name):
    """Legacy URL — redirect to collection view which now shows documents."""
    return redirect(url_for("collection_view", name=name))

@app.route("/collection/<name>/document/<doc_key>/edit")
@require_auth
def document_edit(name, doc_key):
    client = get_client()
    col = client.get_collection(name)
    roles = get_field_roles(name)
    
    # Get all chunks for this document
    all_data = col.get(include=["documents", "metadatas"])
    chunks = []
    meta_base = {}
    for i, doc_id in enumerate(all_data["ids"]):
        if doc_id.startswith(doc_key + "_c"):
            chunks.append({
                "id": doc_id,
                "document": all_data["documents"][i],
                "metadata": all_data["metadatas"][i] if all_data["metadatas"] else {},
            })
            if not meta_base and all_data["metadatas"] and all_data["metadatas"][i]:
                meta_base = {k: v for k, v in all_data["metadatas"][i].items()
                            if k != "index"}
    
    chunks.sort(key=lambda c: c["id"])
    
    # Merge chunks: strip first line (title prefix) + remove overlap
    full_text = ""
    for i, c in enumerate(chunks):
        doc = c["document"]
        # First line is always the 【title】 prefix — strip it
        first_nl = doc.find("\n")
        if first_nl > 0:
            doc = doc[first_nl + 1:]
        # Find overlap: try matching the end of full_text with start of doc
        best = 0
        max_check = min(len(full_text), len(doc), 200)
        for ov in range(20, max_check):
            if full_text[-ov:] == doc[:ov]:
                best = ov
        if best > 0:
            full_text += doc[best:]
        else:
            full_text += "\n" + doc
    title = smart_title(meta_base, roles) or doc_key
    
    return render_template("document_edit.html", current_collection=name, current_view="document_edit",
        name=name, doc_key=doc_key, title=title,
        chunks=chunks, full_text=full_text, meta_base=meta_base)

# API routes with authentication
@app.route("/api/collections")
@require_auth
def api_collections():
    """Return list of collections with counts."""
    client = get_client()
    result = []
    for c in client.list_collections():
        count = c.count()
        doc_count = 0
        if count > 0:
            try:
                all_meta = c.get(include=["metadatas"])["metadatas"]
                keys = set()
                for m in all_meta:
                    k = (m or {}).get("key") or (m or {}).get("__key") or ""
                    if k:
                        keys.add(k)
                doc_count = len(keys) if keys else count
            except Exception:
                doc_count = count
        result.append({"name": c.name, "count": count, "doc_count": doc_count})
    return jsonify(result)

@app.route("/api/roles/<name>")
@require_auth
def api_roles(name):
    """Return auto-detected field roles for a collection."""
    roles = get_field_roles(name)
    return jsonify(roles)

@app.route("/api/search", methods=["POST"])
@require_auth
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

@app.route("/api/update_chunk", methods=["POST"])
@require_auth
def api_update_chunk():
    data = request.json
    col_name = data.get("collection")
    chunk_id = data.get("id")
    new_text = data.get("document")
    new_metadata = data.get("metadata")
    
    if not col_name or not chunk_id or new_text is None:
        return jsonify({"error": "collection, id, and document required"}), 400
    
    col = get_collection(col_name)
    
    update_kwargs = {"ids": [chunk_id], "documents": [new_text]}
    if new_metadata:
        update_kwargs["metadatas"] = [new_metadata]
    
    col.update(**update_kwargs)
    
    # Clear field roles cache
    _field_roles_cache.pop(col_name, None)
    
    return jsonify({"updated": chunk_id, "new_length": len(new_text)})

@app.route("/api/rechunk", methods=["POST"])
@require_auth
def api_rechunk():
    """Re-chunk a document: delete all chunks, re-split, re-embed."""
    data = request.json
    col_name = data.get("collection")
    doc_key = data.get("document_key")
    full_text = data.get("text")
    metadata_base = data.get("metadata", {})
    chunk_size = int(data.get("chunk_size", 600))
    chunk_overlap = int(data.get("overlap", 100))
    
    if not col_name or not doc_key or not full_text:
        return jsonify({"error": "collection, document_key, and text required"}), 400
    
    col = get_collection(col_name)
    
    # 1. Delete existing chunks for this document
    all_ids = col.get()["ids"]
    old_ids = [i for i in all_ids if i.startswith(doc_key + "_c")]
    if old_ids:
        col.delete(ids=old_ids)
    
    # 2. Simple chunking with overlap
    chunks = []
    text = full_text.strip()
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk)
        start = end - chunk_overlap
        if start >= len(text):
            break
    
    # 3. Apply __chunk_prefix to each chunk
    prefix_spec = metadata_base.get("__chunk_prefix", "")
    if prefix_spec:
        parts = [metadata_base.get(k.strip(), "") for k in prefix_spec.split(",")]
        prefix_line = " | ".join(str(p) for p in parts if p)
        if prefix_line:
            chunks = [f"【{prefix_line}】\n{c}" for c in chunks]
    
    # 4. Add new chunks
    new_ids = [f"{doc_key}_c{i:03d}" for i in range(len(chunks))]
    new_metas = []
    for i in range(len(chunks)):
        m = dict(metadata_base)
        m["index"] = i
        new_metas.append(m)
    
    col.add(ids=new_ids, documents=chunks, metadatas=new_metas)
    
    _field_roles_cache.pop(col_name, None)
    
    return jsonify({
        "document_key": doc_key,
        "old_chunks": len(old_ids),
        "new_chunks": len(chunks),
    })

@app.route("/api/delete", methods=["POST"])
@require_auth
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
@require_auth
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