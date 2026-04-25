CHAT_MODEL = "llama3.2"
EMBED_MODEL = "nomic-embed-text"

# Context window token budget (approximate — 1 token ≈ 4 chars)
CONTEXT_TOKEN_BUDGET = 3000

# Trigger summarization when this fraction of the budget is used
SUMMARIZE_THRESHOLD = 0.75

# Keep this many recent messages verbatim; summarize everything older
RECENT_MESSAGES_KEEP = 6

# How many vector memories to inject per turn
MEMORY_TOP_K = 3

# ChromaDB persistence directory
MEMORY_DB_PATH = "./memory_db"
