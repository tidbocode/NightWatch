from config import INTEL_TOP_K
from intel.store import IntelStore


class ThreatIntelRetriever:
    """Query the local threat intelligence vector store for relevant context."""

    def __init__(self, store: IntelStore | None = None):
        self._store = store or IntelStore()

    def retrieve(self, query: str, n: int = INTEL_TOP_K) -> list[str]:
        return self._store.query(query, n_results=n)

    @property
    def available(self) -> bool:
        return self._store.count() > 0
