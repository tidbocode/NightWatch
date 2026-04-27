#!/usr/bin/env python3
"""
Build the NightWatch threat intelligence ChromaDB from MITRE ATT&CK and/or NVD data.

Usage:
    # Download MITRE ATT&CK automatically (requires internet):
    python scripts/build_intel_db.py --download

    # Use a local MITRE ATT&CK STIX JSON you've already downloaded:
    python scripts/build_intel_db.py --mitre /path/to/enterprise-attack.json

    # Add NVD CVE data from a local feed file:
    python scripts/build_intel_db.py --mitre ... --nvd /path/to/nvdcve-1.1-recent.json

    # Limit ingest count (useful for a quick smoke test):
    python scripts/build_intel_db.py --download --limit 50

Prerequisites:
    pip install chromadb
    ollama pull nomic-embed-text
"""
import argparse
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from intel.ingestor import load_mitre_attack, load_nvd_feed
from intel.store import IntelStore

_MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master"
    "/enterprise-attack/enterprise-attack.json"
)


def _upsert_batched(store: IntelStore, chunks: list[dict], batch_size: int = 50) -> None:
    total = len(chunks)
    for i in range(0, total, batch_size):
        store.upsert(chunks[i : i + batch_size])
        done = min(i + batch_size, total)
        print(f"  {done}/{total}", end="\r", flush=True)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the NightWatch threat intelligence database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--mitre", metavar="PATH", help="MITRE ATT&CK enterprise STIX JSON file")
    parser.add_argument("--nvd", metavar="PATH", help="NVD CVE JSON 1.1 feed file")
    parser.add_argument(
        "--download", action="store_true",
        help="Download MITRE ATT&CK enterprise data automatically",
    )
    parser.add_argument(
        "--limit", type=int, default=0, metavar="N",
        help="Cap ingest at N chunks per source (0 = no limit; useful for testing)",
    )
    args = parser.parse_args()

    if not args.mitre and not args.nvd and not args.download:
        parser.print_help()
        sys.exit(1)

    store = IntelStore()
    total_ingested = 0

    # -- MITRE ATT&CK ----------------------------------------------------------
    mitre_path = args.mitre
    if not mitre_path and args.download:
        print("Downloading MITRE ATT&CK enterprise data (~20 MB)...")
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        urllib.request.urlretrieve(_MITRE_URL, tmp.name)
        mitre_path = tmp.name
        print(f"  Saved to {mitre_path}")

    if mitre_path:
        print("Parsing MITRE ATT&CK techniques...")
        chunks = load_mitre_attack(mitre_path)
        if args.limit:
            chunks = chunks[: args.limit]
        print(
            f"  {len(chunks)} techniques — embedding and storing "
            f"(this may take a few minutes)..."
        )
        _upsert_batched(store, chunks)
        print(f"  Done: {len(chunks)} MITRE ATT&CK techniques ingested")
        total_ingested += len(chunks)

    # -- NVD CVEs --------------------------------------------------------------
    if args.nvd:
        print("Parsing NVD CVE feed...")
        chunks = load_nvd_feed(args.nvd)
        if args.limit:
            chunks = chunks[: args.limit]
        print(f"  {len(chunks)} CVEs — embedding and storing...")
        _upsert_batched(store, chunks)
        print(f"  Done: {len(chunks)} CVEs ingested")
        total_ingested += len(chunks)

    print(f"\nTotal chunks in database: {store.count()}")


if __name__ == "__main__":
    main()
