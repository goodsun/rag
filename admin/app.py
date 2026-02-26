#!/usr/bin/env python3
"""ragMyAdmin — ChromaDB Web Frontend with Permission System"""
import os
import sys
import json
import secrets
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort, g
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
import chromadb

# Import authentication module
from auth import (
    require_auth, require_role, phase1_policy, 
    check_rate_limit, log_login_attempt, verify_password, 
    get_client_ip, get_user_info, LOCKOUT_MINUTES,
    audit_log, check_chunk_permission, check_collection_permission,
    # User management functions
    get_all_users, get_user_by_id, create_user, 
    update_user_password, update_user_role, update_user_groups, delete_user,
    get_audit_logs, get_audit_actions
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
# Shared secret key with staff portal for SSO
_staff_key_file = os.path.expanduser('~/.config/staff-auth/secret_key')
if os.path.exists(_staff_key_file):
    with open(_staff_key_file) as _f:
        app.secret_key = _f.read().strip()
else:
    app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)
app.config["APPLICATION_ROOT"] = os.environ.get("APP_ROOT", "/")

# Flask-Session configuration
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(__file__), 'sessions')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECURE_COOKIES', 'true').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_NAME'] = 'staff_session'  # Shared with staff portal for SSO

# CSRF Protection
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
app.config['WTF_CSRF_SECRET_KEY'] = app.secret_key
csrf = CSRFProtect(app)

# Initialize Flask-Session
Session(app)

# CSP nonce generation
@app.before_request
def generate_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)

# Security headers
@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}' 'unsafe-inline'; "
        f"script-src 'self' 'nonce-{nonce}'"
    )
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
        "csp_nonce": getattr(g, 'csp_nonce', ''),
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
    # Get user info for permission checks
    username = session['username']
    user_info = get_user_info(username)
    user_role = user_info['role']
    user_groups = user_info['groups']
    
    # Check collection permission
    if not check_collection_permission(name, username, user_role, required='r'):
        abort(404)  # Hide resource existence
    
    client = get_client()
    col = client.get_collection(name)
    all_data = col.get(include=["documents", "metadatas"])
    
    roles = get_field_roles(name)
    
    # Group by document key (ID before _c), filtering by permissions
    articles = {}
    total_filtered_chunks = 0
    
    for i, doc_id in enumerate(all_data["ids"]):
        meta = all_data["metadatas"][i] if all_data["metadatas"] else {}
        
        # Check chunk-level permission
        if not check_chunk_permission(meta, username, user_role, user_groups, required='r'):
            continue
        
        total_filtered_chunks += 1
        parts = doc_id.rsplit("_c", 1)
        art_key = parts[0] if len(parts) == 2 else doc_id
        
        if art_key not in articles:
            date_field = roles.get("date") or "date"
            articles[art_key] = {
                "key": art_key,
                "title": smart_title(meta, roles) or art_key,
                "url": smart_url(meta, roles),
                "published_at": (meta or {}).get(date_field, ""),
                "chunks": [],
                "total_chars": 0,
                "owner": meta.get('__owner', ''),
            }
        doc_len = len(all_data["documents"][i]) if all_data["documents"][i] else 0
        articles[art_key]["chunks"].append(doc_id)
        articles[art_key]["total_chars"] += doc_len
    
    sorted_articles = sorted(articles.values(), key=lambda a: a.get("published_at", ""), reverse=True)
    
    can_write = check_collection_permission(name, username, user_role, required='w')
    return render_template("documents.html", current_collection=name, current_view="documents",
        name=name, documents=sorted_articles, total=len(sorted_articles), chunk_total=total_filtered_chunks, can_write=can_write)

@app.route("/collection/<name>/document/<doc_key>")
@require_auth
def document_chunks_view(name, doc_key):
    """Show chunks belonging to a specific document."""
    # Get user info for permission checks
    username = session['username']
    user_info = get_user_info(username)
    user_role = user_info['role']
    user_groups = user_info['groups']
    
    # Check collection permission
    if not check_collection_permission(name, username, user_role, required='r'):
        abort(404)  # Hide resource existence
    
    client = get_client()
    col = client.get_collection(name)
    all_result = col.get(include=["documents", "metadatas"])
    
    roles = get_field_roles(name)
    
    # Filter chunks belonging to this document with permission checks
    chunks = []
    doc_title = doc_key
    for i, doc_id in enumerate(all_result["ids"]):
        parts = doc_id.rsplit("_c", 1)
        art_key = parts[0] if len(parts) == 2 else doc_id
        if art_key == doc_key:
            meta = all_result["metadatas"][i] if all_result["metadatas"] else {}
            
            # Check chunk-level permission
            if not check_chunk_permission(meta, username, user_role, user_groups, required='r'):
                continue
            
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
    
    # If no accessible chunks found, return 404 
    if not chunks:
        abort(404)
    
    # Sort by chunk index
    chunks.sort(key=lambda c: c.get("chunk_index", ""))
    
    can_write = check_collection_permission(name, username, user_role, required='w')
    return render_template("collection.html", current_collection=name, current_view="doc_chunks",
        name=name, doc_key=doc_key, doc_title=doc_title, chunks=chunks, total=len(chunks), can_write=can_write)

@app.route("/collection/<name>/chunk/<chunk_id>")
@require_auth
def chunk_detail(name, chunk_id):
    # Get user info for permission checks
    username = session['username']
    user_info = get_user_info(username)
    user_role = user_info['role']
    user_groups = user_info['groups']
    
    # Check collection permission
    if not check_collection_permission(name, username, user_role, required='r'):
        abort(404)  # Hide resource existence
    
    client = get_client()
    col = client.get_collection(name)
    result = col.get(ids=[chunk_id], include=["documents", "metadatas", "embeddings"])
    
    if not result["ids"]:
        abort(404)
    
    chunk_meta = result["metadatas"][0] if result["metadatas"] else {}
    
    # Check chunk-level permission
    if not check_chunk_permission(chunk_meta, username, user_role, user_groups, required='r'):
        abort(404)  # Hide resource existence
    
    chunk = {
        "id": result["ids"][0],
        "document": result["documents"][0],
        "metadata": chunk_meta,
        "embedding_dim": len(result["embeddings"][0]) if result["embeddings"] is not None and len(result["embeddings"]) > 0 else 0,
        "embedding_preview": list(result["embeddings"][0][:10]) if result["embeddings"] is not None and len(result["embeddings"]) > 0 else [],
    }
    
    # Check if user has write permission for editing/deleting
    can_write = check_chunk_permission(chunk_meta, username, user_role, user_groups, required='w')
    
    return render_template("chunk_detail.html", 
                         current_collection=name, 
                         current_view="chunk_detail", 
                         name=name, 
                         chunk=chunk,
                         user_role=user_role,
                         can_write=can_write)

@app.route("/collection/<name>/documents")
@require_auth
def documents_view(name):
    """Legacy URL — redirect to collection view which now shows documents."""
    return redirect(url_for("collection_view", name=name))

@app.route("/collection/<name>/document/<doc_key>/edit", methods=["GET"])
@require_auth
def document_edit(name, doc_key):
    # Permission check: require write access
    username = session['username']
    user_info = get_user_info(username)
    user_role = user_info['role']
    user_groups = user_info['groups']
    
    if not check_collection_permission(name, username, user_role, required='w'):
        abort(403)
    
    client = get_client()
    col = client.get_collection(name)
    roles = get_field_roles(name)
    
    # Get all chunks for this document
    all_data = col.get(include=["documents", "metadatas"])
    chunks = []
    meta_base = {}
    for i, doc_id in enumerate(all_data["ids"]):
        if doc_id.startswith(doc_key + "_c"):
            meta = all_data["metadatas"][i] if all_data["metadatas"] else {}
            # Check chunk-level write permission
            if not check_chunk_permission(meta, username, user_role, user_groups, required='w'):
                abort(403)
            chunks.append({
                "id": doc_id,
                "document": all_data["documents"][i],
                "metadata": meta,
            })
            if not meta_base and meta:
                meta_base = {k: v for k, v in meta.items()
                            if k != "index"}
    
    if not chunks:
        abort(404)
    
    chunks.sort(key=lambda c: c["id"])
    
    # Merge chunks: strip __chunk_prefix line + remove overlap
    full_text = ""
    prefix_spec = meta_base.get("__chunk_prefix", "")
    for i, c in enumerate(chunks):
        doc = c["document"]
        # Strip chunk prefix (first line like 【...】)
        if doc.startswith("【"):
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
            if full_text:
                full_text += "\n" + doc
            else:
                full_text = doc
    title = smart_title(meta_base, roles) or doc_key
    
    return render_template("document_edit.html", current_collection=name, current_view="document_edit",
        name=name, doc_key=doc_key, title=title,
        chunks=chunks, full_text=full_text.strip(), meta_base=meta_base)

# API routes with authentication
@app.route("/api/collections")
@csrf.exempt
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
@csrf.exempt
@require_auth
def api_search():
    data = request.json
    col_name = data.get("collection", "note_articles")
    query = data.get("query", "")
    n_results = int(data.get("n_results", 10))
    
    # Get user info for permission checks
    username = session['username']
    user_info = get_user_info(username)
    user_role = user_info['role']
    user_groups = user_info['groups']
    
    # Check collection permission
    if not check_collection_permission(col_name, username, user_role, required='r'):
        return jsonify({"results": [], "query": query, "collection": col_name, "error": "No access to collection"})
    
    client = get_client()
    col = client.get_collection(col_name)
    
    # Get more results initially to account for filtering
    search_limit = min(n_results * 3, 100)  # Request extra to account for filtering
    
    # __visibility='private' のチャンクを除外
    results = col.query(
        query_texts=[query],
        n_results=search_limit,
        include=["documents", "metadatas", "distances"],
        where={"$or": [
            {"__visibility": {"$ne": "private"}},
            {"__visibility": {"$exists": False}}
        ]}
    )
    
    items = []
    for i, doc_id in enumerate(results["ids"][0]):
        metadata = results["metadatas"][0][i] if results["metadatas"] else {}
        
        # Check chunk-level permission
        if check_chunk_permission(metadata, username, user_role, user_groups, required='r'):
            items.append({
                "id": doc_id,
                "document": results["documents"][0][i],
                "metadata": metadata,
                "distance": round(results["distances"][0][i], 4) if results["distances"] else None,
            })
            
            # Stop when we have enough results
            if len(items) >= n_results:
                break
    
    return jsonify({"results": items, "query": query, "collection": col_name})

@app.route("/api/update_chunk", methods=["POST"])
@csrf.exempt
@require_auth
def api_update_chunk():
    try:
        data = request.json
        col_name = data.get("collection")
        chunk_id = data.get("id")
        new_text = data.get("document")
        new_metadata = data.get("metadata")
        
        if not col_name or not chunk_id or new_text is None:
            return jsonify({"error": "collection, id, and document required"}), 400
        
        # Get user info for permission checks
        username = session['username']
        user_info = get_user_info(username)
        user_role = user_info['role']
        user_groups = user_info['groups']
        
        # Check collection permission
        if not check_collection_permission(col_name, username, user_role, required='w'):
            abort(404)  # Hide resource existence
        
        col = get_collection(col_name)
        
        # Get current chunk metadata for permission check
        try:
            existing_chunk = col.get(ids=[chunk_id], include=['metadatas'])
            if not existing_chunk['ids']:
                abort(404)
            
            chunk_meta = existing_chunk['metadatas'][0] or {}
        except:
            abort(404)
        
        # Check chunk-level permission
        if not check_chunk_permission(chunk_meta, username, user_role, user_groups, required='w'):
            abort(404)  # Hide resource existence
        
        # Update chunk metadata to include editor info
        if new_metadata:
            if '__owner' not in new_metadata and '__owner' not in chunk_meta:
                new_metadata['__owner'] = username
            new_metadata['__modified_by'] = username
            new_metadata['__modified_at'] = datetime.now().isoformat()
        else:
            new_metadata = chunk_meta.copy()
            new_metadata['__modified_by'] = username
            new_metadata['__modified_at'] = datetime.now().isoformat()
        
        update_kwargs = {"ids": [chunk_id], "documents": [new_text]}
        if new_metadata:
            update_kwargs["metadatas"] = [new_metadata]
        
        col.update(**update_kwargs)
        
        # Audit log
        audit_log(username, 'edit', {'action': 'update_chunk', 'collection': col_name, 'chunk_id': chunk_id}, target=chunk_id)
        
        # Clear field roles cache
        _field_roles_cache.pop(col_name, None)
        
        return jsonify({"updated": chunk_id, "new_length": len(new_text)})
        
    except Exception as e:
        app.logger.error(f"api_update_chunk error for user {session.get('username')}: {str(e)}")
        return jsonify({"error": "チャンクの更新中にエラーが発生しました"}), 500

@app.route("/api/rechunk", methods=["POST"])
@csrf.exempt
@require_auth
def api_rechunk():
    """Re-chunk a document: delete all chunks, re-split, re-embed."""
    try:
        data = request.json
        col_name = data.get("collection")
        doc_key = data.get("document_key")
        full_text = data.get("text")
        metadata_base = data.get("metadata", {})
        chunk_size = int(data.get("chunk_size", 600))
        chunk_overlap = int(data.get("overlap", 100))
        
        if not col_name or not doc_key or not full_text:
            return jsonify({"error": "collection, document_key, and text required"}), 400
        
        # Get user info for permission checks
        username = session['username']
        user_info = get_user_info(username)
        user_role = user_info['role']
        user_groups = user_info['groups']
        
        # Check collection permission - rechunking requires admin/editor
        if not check_collection_permission(col_name, username, user_role, required='w'):
            abort(404)  # Hide resource existence
        
        col = get_collection(col_name)
        
        # 1. Check permissions for existing chunks before deletion
        all_ids = col.get()["ids"]
        old_ids = [i for i in all_ids if i.startswith(doc_key + "_c")]
        
        # Check if user has permission to delete existing chunks
        allowed_to_rechunk = True
        if old_ids:
            for chunk_id in old_ids:
                try:
                    existing_chunk = col.get(ids=[chunk_id], include=['metadatas'])
                    if existing_chunk['ids']:
                        chunk_meta = existing_chunk['metadatas'][0] or {}
                        if not check_chunk_permission(chunk_meta, username, user_role, user_groups, required='w'):
                            allowed_to_rechunk = False
                            break
                except:
                    # If we can't access the chunk, assume no permission
                    allowed_to_rechunk = False
                    break
        
        if not allowed_to_rechunk:
            abort(404)  # User doesn't have permission to rechunk this document
        
        # Delete existing chunks
        if old_ids:
            col.delete(ids=old_ids)
        
        # 2. Paragraph-aware chunking
        chunks = []
        text = full_text.strip()
        paragraphs = text.split("\n")
        current_chunk = ""
        for para in paragraphs:
            candidate = (current_chunk + "\n" + para).strip() if current_chunk else para.strip()
            if len(candidate) > chunk_size and current_chunk:
                chunks.append(current_chunk)
                current_chunk = para.strip()
            else:
                current_chunk = candidate
            # Hard split if single paragraph exceeds chunk_size
            while len(current_chunk) > chunk_size:
                chunks.append(current_chunk[:chunk_size])
                current_chunk = current_chunk[chunk_size - chunk_overlap:] if chunk_overlap else current_chunk[chunk_size:]
        if current_chunk.strip():
            chunks.append(current_chunk)
        
        # 3. Apply __chunk_prefix to each chunk
        prefix_spec = metadata_base.get("__chunk_prefix", "")
        if prefix_spec:
            parts = [metadata_base.get(k.strip(), "") for k in prefix_spec.split(",")]
            prefix_line = " | ".join(str(p) for p in parts if p)
            if prefix_line:
                chunks = [f"【{prefix_line}】\n{c}" for c in chunks]
        
        # 4. Add ownership metadata to new chunks
        for i in range(len(chunks)):
            meta = dict(metadata_base)
            meta["index"] = i
            if '__owner' not in meta:
                meta['__owner'] = username
            meta['__created_by'] = username
            meta['__created_at'] = datetime.now().isoformat()
            metadata_base = meta
            break
        
        # Create metadata for each chunk
        new_ids = [f"{doc_key}_c{i:03d}" for i in range(len(chunks))]
        new_metas = []
        for i in range(len(chunks)):
            m = dict(metadata_base)
            m["index"] = i
            new_metas.append(m)
        
        col.add(ids=new_ids, documents=chunks, metadatas=new_metas)
        
        # Audit log
        audit_log(username, 'rechunk', {'action': 'rechunk_document', 'collection': col_name, 'document_key': doc_key, 'old_chunks': len(old_ids), 'new_chunks': len(chunks)}, target=doc_key)
        
        _field_roles_cache.pop(col_name, None)
        
        return jsonify({
            "document_key": doc_key,
            "old_chunks": len(old_ids),
            "new_chunks": len(chunks),
        })
        
    except Exception as e:
        app.logger.error(f"api_rechunk error for user {session.get('username')}: {str(e)}")
        return jsonify({"error": "ドキュメントの再チャンク中にエラーが発生しました"}), 500

@app.route("/api/delete", methods=["POST"])
@csrf.exempt
@require_auth
def api_delete():
    try:
        data = request.json
        col_name = data.get("collection")
        chunk_ids = data.get("ids", [])
        
        if not col_name or not chunk_ids:
            return jsonify({"error": "collection and ids required"}), 400
        
        # Get user info for permission checks
        username = session['username']
        user_info = get_user_info(username)
        user_role = user_info['role']
        user_groups = user_info['groups']
        
        # Check collection permission
        if not check_collection_permission(col_name, username, user_role, required='w'):
            abort(404)  # Hide resource existence
        
        client = get_client()
        col = client.get_collection(col_name)
        
        # Check permission for each chunk before deleting
        allowed_ids = []
        for chunk_id in chunk_ids:
            try:
                existing_chunk = col.get(ids=[chunk_id], include=['metadatas'])
                if existing_chunk['ids']:
                    chunk_meta = existing_chunk['metadatas'][0] or {}
                    if check_chunk_permission(chunk_meta, username, user_role, user_groups, required='w'):
                        allowed_ids.append(chunk_id)
            except:
                # Ignore chunks that don't exist or can't be accessed
                continue
        
        if not allowed_ids:
            abort(404)  # No chunks found or no permission
        
        # Delete only allowed chunks
        col.delete(ids=allowed_ids)
        
        # Audit log for each deleted chunk
        for chunk_id in allowed_ids:
            audit_log(username, 'delete', {'action': 'delete_chunk', 'collection': col_name, 'chunk_id': chunk_id}, target=chunk_id)
        
        return jsonify({"deleted": len(allowed_ids), "remaining": col.count()})
        
    except Exception as e:
        app.logger.error(f"api_delete error for user {session.get('username')}: {str(e)}")
        return jsonify({"error": "チャンクの削除中にエラーが発生しました"}), 500

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

# User management routes (admin only)

@app.route("/users")
@require_auth
@require_role('admin')
def users_list():
    """Users management page (admin only)"""
    users = get_all_users()
    current_user = session.get('username')
    
    # Parse groups JSON for display
    for user in users:
        try:
            user['groups_list'] = json.loads(user['groups'])
        except (json.JSONDecodeError, TypeError):
            user['groups_list'] = []
    
    return render_template('users.html', 
                         users=users, 
                         current_user=current_user)

@app.route("/users/add", methods=["GET", "POST"])
@require_auth  
@require_role('admin')
def users_add():
    """Add new user (admin only)"""
    if request.method == "GET":
        return render_template('user_add.html')
    
    # POST - create user
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    password_confirm = request.form.get('password_confirm', '')
    role = request.form.get('role', 'viewer')
    groups = request.form.get('groups', '').strip()
    
    # Server-side validation
    errors = []
    
    if not username:
        errors.append("ユーザー名は必須です")
    
    if not password:
        errors.append("パスワードは必須です")
    elif password != password_confirm:
        errors.append("パスワードが一致しません")
    
    if errors:
        return render_template('user_add.html', 
                             errors=errors,
                             username=username,
                             role=role,
                             groups=groups), 400
    
    # Create user
    try:
        success, message = create_user(username, password, role, groups)
    except Exception as e:
        app.logger.error(f"create_user error: {e}")
        success, message = False, f"ユーザー作成中にエラーが発生しました: {e}"
    
    if success:
        try:
            audit_log(session['username'], 'admin_user_add', {'target_user': username})
        except Exception:
            pass
        flash(message, 'success')
        return redirect(url_for('users_list'))
    else:
        return render_template('user_add.html', 
                             errors=[message],
                             username=username,
                             role=role,
                             groups=groups), 400

@app.route("/audit")
@require_auth
@require_role('admin')
def audit_logs():
    """Audit logs viewer (admin only)"""
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 200)  # Limit max per_page
    offset = (page - 1) * per_page
    
    # Filters
    username_filter = request.args.get('username', '').strip()
    action_filter = request.args.get('action', '').strip()
    
    if username_filter == '':
        username_filter = None
    if action_filter == '':
        action_filter = None
    
    # Get logs
    result = get_audit_logs(
        limit=per_page, 
        offset=offset,
        username_filter=username_filter,
        action_filter=action_filter
    )
    
    # Pagination info
    total_pages = (result['total'] + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    # Parse detail JSON for display
    for log in result['logs']:
        if log['detail']:
            try:
                log['detail_parsed'] = json.loads(log['detail'])
            except json.JSONDecodeError:
                log['detail_parsed'] = {'raw': log['detail']}
        else:
            log['detail_parsed'] = {}
    
    # Get available actions for filter
    available_actions = get_audit_actions()
    
    return render_template('audit.html',
                         logs=result['logs'],
                         total=result['total'],
                         page=page,
                         per_page=per_page,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         username_filter=username_filter or '',
                         action_filter=action_filter or '',
                         available_actions=available_actions)

# User management API endpoints

@app.route("/api/user/<int:user_id>/password", methods=["POST"])
@csrf.exempt
@require_auth
@require_role('admin')
def api_update_user_password(user_id):
    """Update user password"""
    new_password = request.json.get('password', '').strip()
    
    if not new_password:
        return jsonify({"success": False, "message": "パスワードは必須です"}), 400
    
    success, message = update_user_password(user_id, new_password, session['username'])
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400

@app.route("/api/user/<int:user_id>/role", methods=["POST"])
@csrf.exempt
@require_auth
@require_role('admin')
def api_update_user_role(user_id):
    """Update user role"""
    new_role = request.json.get('role', '').strip()
    
    if not new_role:
        return jsonify({"success": False, "message": "ロールは必須です"}), 400
    
    success, message = update_user_role(user_id, new_role, session['username'])
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400

@app.route("/api/user/<int:user_id>/groups", methods=["POST"])
@csrf.exempt
@require_auth
@require_role('admin')
def api_update_user_groups(user_id):
    """Update user groups"""
    new_groups = request.json.get('groups', '')
    
    success, message = update_user_groups(user_id, new_groups, session['username'])
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400

@app.route("/api/user/<int:user_id>/delete", methods=["POST"])
@csrf.exempt
@require_auth
@require_role('admin')
def api_delete_user(user_id):
    """Delete user"""
    success, message = delete_user(user_id, session['username'])
    
    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8792))
    prefix = os.environ.get("APP_ROOT", "")
    if prefix:
        app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix=prefix)
    app.run(host="0.0.0.0", port=port, debug=False)