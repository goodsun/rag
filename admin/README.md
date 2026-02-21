# 🗄️ ragMyAdmin

**A phpMyAdmin-inspired web frontend for ChromaDB.**

ragMyAdmin provides a familiar, intuitive interface for browsing, searching, and managing vector database contents — just like phpMyAdmin did for MySQL.

## Concepts

### Data Hierarchy

```
Collection → Document → Chunk
```

| ragMyAdmin | Description | ChromaDB Mapping |
|---|---|---|
| **Collection** | A named group of vectors (like a DB table) | Collection |
| **Document** | A logical grouping of related chunks (e.g., an article, PDF, webpage) | *(inferred from metadata/ID)* |
| **Chunk** | An individual text segment with its embedding vector | Document (ChromaDB's term) |

> **Note on terminology:** "Document" in ragMyAdmin refers to a **LogicalDocument** — a group of chunks derived from the same source, inferred from metadata or ID naming conventions (e.g., `article123_c000`, `article123_c001`). This is distinct from ChromaDB's internal use of "document" to mean the text content of a single vector entry.

### Why LogicalDocument?

Vector databases store flat collections of chunks. But humans think in terms of *sources* — "which article is this from?" ragMyAdmin bridges this gap by reconstructing document-level structure from chunk metadata, giving you a **3-tier hierarchy** over a 2-tier reality.

This is the same philosophy as phpMyAdmin: the tool doesn't just mirror the database's internal model — it presents a **human-friendly view** on top of it.

## Features

- 📊 **Dashboard** — Collection overview with stats
- 📰 **Document Browser** — Chunks grouped by source document
- 📋 **Chunk Browser** — Paginated list with text filter, per-page control
- 📄 **Chunk Detail** — Full content, metadata, embedding info, similar chunks
- 🔍 **Semantic Search** — Query vectors and see results ranked by distance
- 📊 **Statistics** — Source distribution, chunk length stats (min/avg/median/max)
- 🗑️ **Delete** — Individual chunks, bulk select, or entire documents

## Setup

### Requirements

- Python 3.9+
- Flask (`pip install flask`)
- ChromaDB (`pip install chromadb`)

### Quick Start

```bash
cd admin/
CHROMA_PATH=/path/to/chroma_db python3 app.py
# → http://localhost:8792
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CHROMA_PATH` | `../chroma_db` | Path to ChromaDB persistent storage |
| `PORT` | `8792` | Server port |
| `APP_ROOT` | `` | URL prefix for reverse proxy (e.g., `/ragmyadmin`) |

### Reverse Proxy (Apache)

```apache
<Location /ragmyadmin/>
    AuthType Basic
    AuthName "ragMyAdmin"
    AuthUserFile /path/to/.htpasswd
    Require valid-user
    ProxyPass http://127.0.0.1:8792/
    ProxyPassReverse http://127.0.0.1:8792/
</Location>
```

### systemd Service

```ini
[Unit]
Description=ragMyAdmin
After=network.target

[Service]
User=ec2-user
WorkingDirectory=/path/to/rag/admin
ExecStart=/usr/bin/python3 -u app.py
Restart=always
Environment=PORT=8792
Environment=CHROMA_PATH=/path/to/chroma_db
Environment=APP_ROOT=/ragmyadmin

[Install]
WantedBy=multi-user.target
```

## Document Grouping

ragMyAdmin infers LogicalDocuments from chunk IDs using the convention:

```
{document_key}_c{chunk_index:03d}
```

For example:
- `n0e49dfa613a8_c000` → Document `n0e49dfa613a8`, Chunk 0
- `n0e49dfa613a8_c001` → Document `n0e49dfa613a8`, Chunk 1

This convention is configurable and can be adapted to other ID schemes.

## Inspired By

[phpMyAdmin](https://www.phpmyadmin.net/) 🐬 — the tool that made databases accessible to everyone.

ragMyAdmin aims to do the same for vector databases.

## License

MIT
