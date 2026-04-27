import chromadb
import ollama

from config import EMBED_MODEL, INTEL_DB_PATH


class IntelStore:
    """Persistent ChromaDB collection for threat intelligence chunks."""

    def __init__(self, db_path: str = INTEL_DB_PATH):
        self._client = chromadb.PersistentClient(path=db_path)
        self._col = self._client.get_or_create_collection(
            name="threat_intel",
            metadata={"hnsw:space": "cosine"},
        )

    def upsert(self, chunks: list[dict]) -> None:
        """Insert or update chunks. Each chunk: {"id": str, "text": str, "metadata": dict}"""
        if not chunks:
            return
        ids = [c["id"] for c in chunks]
        texts = [c["text"] for c in chunks]
        metadatas = [c.get("metadata", {}) for c in chunks]
        embeddings = [_embed(t) for t in texts]
        self._col.upsert(
            ids=ids,
            documents=texts,
            embeddings=embeddings,
            metadatas=metadatas,
        )

    def query(self, text: str, n_results: int = 3) -> list[str]:
        """Return the top-n most relevant document texts for the query."""
        total = self._col.count()
        if total == 0:
            return []
        results = self._col.query(
            query_embeddings=[_embed(text)],
            n_results=min(n_results, total),
        )
        return results["documents"][0]

    def count(self) -> int:
        return self._col.count()


def _embed(text: str) -> list[float]:
    try:
        resp = ollama.embeddings(model=EMBED_MODEL, prompt=text)
        return list(resp.embedding)
    except AttributeError:
        # Newer ollama SDK uses embed() returning embeddings (plural)
        resp = ollama.embed(model=EMBED_MODEL, input=text)
        return list(resp.embeddings[0])
