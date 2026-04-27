![Image](https://github.com/tidbocode/NightWatch/blob/main/NightWatch.jpg)

# NightWatch

A fully local, privacy-first log analyzer that uses a local LLM (via Ollama) to detect security threats in your log files — no cloud, no data leaving your machine.

| Capability | Details |
|---|---|
| **Threat detection** | Brute force, SQLi/XSS, path traversal, privilege escalation, port scanning, suspicious user agents, backdoor accounts, C2 patterns |
| **Log formats** | syslog / auth.log, nginx/apache CLF, JSON logs, Windows Event Log CSV |
| **Alert persistence** | SQLite database — query by severity, IP, source file, or free text |
| **Models** | `mistral:7b` for analysis · `llama3.2` for fast watch mode |
| **Threat intel RAG** | MITRE ATT&CK + NVD CVE context injected into every analysis prompt |

## Prerequisites

- [Ollama](https://ollama.com) installed and running (`ollama serve`)
- Python 3.11+

## Setup

```bash
# 1. Pull the required models
ollama pull mistral:7b
ollama pull llama3.2

# 2. Install Python dependencies
pip install -r requirements.txt
```

### Optional: Threat Intelligence RAG

Enriches every analysis with relevant MITRE ATT&CK techniques and CVE references, retrieved locally via ChromaDB. Alerts will include technique IDs (e.g. T1110), tactic names, and CVE context.

```bash
# 1. Pull the embedding model
ollama pull nomic-embed-text

# 2. Build the vector database (downloads ~20 MB of MITRE ATT&CK data)
python scripts/build_intel_db.py --download
```

Once `./nightwatch_intel/` exists, NightWatch loads it automatically — no extra flags needed. To also include NVD CVE data, download a feed from [nvd.nist.gov](https://nvd.nist.gov/vuln/data-feeds) and pass it with `--nvd`:

```bash
python scripts/build_intel_db.py --download --nvd /path/to/nvdcve-1.1-recent.json
```

## Usage

### Batch — analyze a log file

```bash
python main.py batch --file /var/log/auth.log
python main.py batch --file /var/log/nginx/access.log --format clf
python main.py batch --file auth.log --min-severity HIGH --output alerts.json
python main.py batch --file auth.log --fast          # use llama3.2 for speed
```

### Watch — tail a live log file

```bash
python main.py watch --file /var/log/auth.log
python main.py watch --file /var/log/nginx/access.log --interval 10
```

Tails the file from the current end. Buffers new lines, analyzes them in batches, and displays alerts as they arrive. Press Ctrl-C to stop.

### Query — search stored alerts

```bash
python main.py query
```

Opens an interactive REPL to query the alert database:

| Command | Description |
|---|---|
| `/findings` | 20 most recent alerts |
| `/top-iocs` | Most frequently seen IOCs |
| `/stats` | Database summary |
| `/severity HIGH` | Filter by minimum severity |
| `/ip 1.2.3.4` | Find alerts involving an IP |
| `/source /var/log/auth.log` | Alerts from a specific file |
| `/clear` | Delete all stored alerts |
| `/help` | Show all commands |
| any text | Free-text search across titles and descriptions |

## Alert severity levels

| Severity | Meaning |
|---|---|
| `CRITICAL` | Active exploitation, confirmed breach, RCE, ransomware |
| `HIGH` | Brute force, SQLi/XSS attempts, port scanning, privilege escalation |
| `MEDIUM` | Repeated failures, suspicious patterns, unusual access |
| `LOW` | Single failed login, minor anomaly |
| `INFO` | Notable but non-threatening event |

## Architecture

```
Log file / stdin
      │
      ▼
FormatDetector → LogParser (syslog / CLF / JSON / Windows CSV)
      │
      ▼                        Iterator[LogEntry]
ThreatAnalyzer
  ├── Chunks entries to fit token budget (~1500 tokens/chunk)
  ├── Retrieves relevant MITRE ATT&CK / CVE snippets from ChromaDB  ← RAG
  ├── Builds layered prompt: system → threat intel context → rolling context → log chunk
  ├── Streams response from Ollama (mistrat:7b)
  ├── Parses JSON → list[Alert]
  └── Persists each Alert to SQLite (nightwatch.db)
      │
      ▼
Rich console — color-coded panels per alert
```

### RAG pipeline

```
Ingest (one-time)
  MITRE ATT&CK JSON / NVD CVE feed
        │
        ▼
  nomic-embed-text (Ollama) → vector embeddings → ChromaDB (nightwatch_intel/)

Analysis (per log chunk)
  log chunk text → embed → cosine similarity search → top-3 intel snippets
                                                            │
                                                            ▼
                                               injected into system prompt
```

## Configuration

Edit `config.py` to change models, chunk size, or database path.

| Variable | Default | Effect |
|---|---|---|
| `CHAT_MODEL` | `mistral:7b` | Model used for batch analysis |
| `FAST_MODEL` | `llama3.2` | Model used for watch mode |
| `CHUNK_TOKEN_BUDGET` | `1500` | Max tokens per log chunk sent to LLM |
| `MIN_SEVERITY` | `LOW` | Default minimum severity to display |
| `ALERT_DB_PATH` | `./nightwatch.db` | SQLite database location |
| `EMBED_MODEL` | `nomic-embed-text` | Ollama model used to embed intel chunks and queries |
| `INTEL_DB_PATH` | `./nightwatch_intel` | ChromaDB directory for threat intelligence |
| `INTEL_TOP_K` | `3` | Number of intel snippets retrieved per log chunk |

## Running tests

```bash
pytest tests/
```
