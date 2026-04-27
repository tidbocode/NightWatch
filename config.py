CHAT_MODEL = "mistral:7b"
FAST_MODEL = "llama3.2"          # used for watch mode where speed matters more than accuracy

# Token budget per log chunk sent to the LLM (approximate — 1 token ≈ 4 chars)
CHUNK_TOKEN_BUDGET = 1500

# Minimum alert severity to display: CRITICAL, HIGH, MEDIUM, LOW, INFO
MIN_SEVERITY = "LOW"

# Max raw log lines to include in a single Alert's affected_lines list
MAX_AFFECTED_LINES = 10

# SQLite database path for alert persistence
ALERT_DB_PATH = "./nightwatch.db"

# LLM generation — low temperature for consistent JSON output
LLM_TEMPERATURE = 0.1

# Threat intelligence RAG (requires: pip install chromadb && ollama pull nomic-embed-text)
EMBED_MODEL = "nomic-embed-text"   # embedding model served by Ollama
INTEL_DB_PATH = "./nightwatch_intel"  # ChromaDB directory; auto-detected at startup
INTEL_TOP_K = 3                    # retrieved snippets injected per prompt
