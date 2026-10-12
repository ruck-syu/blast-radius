"""Shared config: FalkorDB connection + graph names per org."""
import os

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
