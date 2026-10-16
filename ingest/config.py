"""Shared config: FalkorDB connection + graph names per org.

Loads <repo>/.env on import (stdlib, no python-dotenv); variables already set in
the process environment win, so `FOO=x python -m ...` still overrides .env.
"""
import os
from pathlib import Path


def _load_dotenv(path: Path = Path(__file__).resolve().parent.parent / ".env") -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        value = value.split(" #", 1)[0].strip().strip("'\"")
        if key and value:
            os.environ.setdefault(key, value)


_load_dotenv()

HOST = os.getenv("FALKORDB_HOST", "localhost")
PORT = int(os.getenv("FALKORDB_PORT", "6379"))
USERNAME = os.getenv("FALKORDB_USERNAME") or None
PASSWORD = os.getenv("FALKORDB_PASSWORD") or None

GRAPH_FOR_ORG = {
    "dev": os.getenv("BLAST_GRAPH", "blast_radius_dev"),
    "heldout": os.getenv("BLAST_HELDOUT_GRAPH", "blast_radius_heldout"),
}

MAX_DEP_DEPTH = int(os.getenv("BLAST_MAX_DEP_DEPTH", "6"))
MAX_CALL_DEPTH = int(os.getenv("BLAST_MAX_CALL_DEPTH", "4"))


def graph_name(org: str) -> str:
    if org not in GRAPH_FOR_ORG:
        raise ValueError(f"unknown org {org!r}, expected one of {list(GRAPH_FOR_ORG)}")
    return GRAPH_FOR_ORG[org]
