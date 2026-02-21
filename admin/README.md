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

## Dunder (`__`) Metadata Convention

ragMyAdmin uses a **dunder (double underscore) prefix convention** to separate control metadata from data metadata. Inspired by Python's dunder methods and Elasticsearch's `copy_to` technique.

### Standard Dunder Fields

| Field | Role | Description |
|---|---|---|
| `__key` | Key | Document grouping key (chunk ID prefix) |
| `__title` | Title | Display title for the document |
| `__url` | URL | Original source URL |
| `__date` | Date | Publication or creation date |
| `__index` | Index | Chunk order within document (auto-assigned by chunker) |
| `__total` | Total | Total chunks in document (auto-assigned by chunker) |

### Behavioral Dunders

These control **how chunking and embedding work**, not what data is stored:

| Field | Description | Example |
|---|---|---|
| `__chunk_prefix` | Comma-separated metadata key names to prepend to each chunk's text | `"__title"` → `【タイトル】\nチャンク本文...` |
| | | `"__title, tags, author"` → `【タイトル \| タグ \| 著者】\nチャンク本文...` |

The `__chunk_prefix` value **references other metadata keys by name**. The chunker resolves these references and prepends the values to each chunk's document text, improving semantic search relevance by embedding metadata into the vector.

### Resolution Priority

ragMyAdmin resolves field roles in this order:

1. **Dunder fields** (`__title`, `__url`, etc.) — highest priority
2. **Auto-detection** — pattern-based analysis of values (URLs, dates, etc.)
3. **Hardcoded fallback** — legacy key names (`article_title`, `document_title`, etc.)

This means:
- **New collections**: Use dunders and everything Just Works™
- **Legacy collections**: Auto-detection handles them without migration
- **Mixed state**: Dunders and legacy keys can coexist during migration

### Design Philosophy

- `__`-prefixed fields = **instructions** (how to process)
- Regular fields = **data** (what to store and display)
- Minimal required structure + free-form extension = maximum flexibility
- **Convention over configuration**: no schema definition needed

## Features

- 📊 **Dashboard** — Collection overview with stats and auto-detected field roles
- 📰 **Document Browser** — Chunks grouped by source document
- 📋 **Chunk Browser** — Paginated list with text filter, per-page control
- 📄 **Chunk Detail** — Full content, metadata, embedding info, similar chunks
- ✏️ **Document Editor** — Edit merged document text, re-chunk and re-embed
- 🔍 **Semantic Search** — Query vectors and see results ranked by distance
- 📊 **Statistics** — Source distribution, chunk length stats (min/avg/median/max)
- 🗑️ **Delete** — Individual chunks, bulk select, or entire documents
- 🔍 **Auto-Detection** — Metadata field roles detected automatically from values

## Pipeline

```
Source → Scraper → raw/*.json → Chunker → chunks/all_chunks.json → Embedder → ChromaDB
```

### Scraper (`scrape_note.py`)
Fetches articles from note.com API and saves as raw JSON.

### Chunker (`chunker.py`)
Splits articles into chunks with:
- Section-aware splitting (respects `##` headings and paragraph boundaries)
- Configurable chunk size (default: 600 chars) and overlap (default: 100 chars)
- `__chunk_prefix` support (embeds metadata into chunk text)
- Dunder + legacy key dual output for backward compatibility

### Embedder (`embed.py`)
Loads chunks into ChromaDB with:
- `--collection` flag for multi-collection support
- `--append` mode for incremental updates
- fastembed (`paraphrase-multilingual-MiniLM-L12-v2`) for multilingual embedding

## Setup

### Requirements

- Python 3.9+
- Flask (`pip install flask`)
- ChromaDB (`pip install chromadb`)
- fastembed (`pip install fastembed`) — for embedding and search

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
{__key}_c{__index:03d}
```

For example:
- `n0e49dfa613a8_c000` → Document `n0e49dfa613a8`, Chunk 0
- `n0e49dfa613a8_c001` → Document `n0e49dfa613a8`, Chunk 1
- `xpathgenie_wp_c000` → Document `xpathgenie_wp`, Chunk 0

## Inspired By

- [phpMyAdmin](https://www.phpmyadmin.net/) 🐬 — Made databases accessible to everyone
- [Kibana](https://www.elastic.co/kibana) 📊 — Document-oriented thinking for search
- Elasticsearch's `copy_to` — Embedding metadata into searchable fields

ragMyAdmin combines phpMyAdmin's **point-and-click UX** with Kibana's **document-oriented philosophy**, without Kibana's complex query DSL.

## License

MIT
