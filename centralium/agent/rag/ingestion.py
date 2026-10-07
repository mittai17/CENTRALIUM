"""Knowledge ingestion: rag/documents/*.{md,json} -> chunks -> embeddings -> VectorStore.

Formats
* ``*.md``   - optional front matter (``source:``, ``title:``, ``tags:``) then ``## `` sections;
               each section is one chunk ``<stem>#<slug>``.
* ``*.json`` - ``{"source": "mitre", "techniques": [{id,name,tactic,platforms,description,detection}]}``
               or ``{"source": "...", "documents": [{doc_id,title,text,metadata}]}``.
Ingestion is incremental (content hash) and removes chunks whose file disappeared.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from centralium.agent.rag.embedder import Embedder
from centralium.agent.rag.store import StoredDoc, VectorStore

log = logging.getLogger("centralium.rag.ingest")

MAX_CHUNK_CHARS = 1600
INDEX_VERSION_KEY = "index_version"


@dataclass
class IngestReport:
    files: int = 0
    chunks: int = 0
    added: int = 0
    updated: int = 0
    unchanged: int = 0
    removed: int = 0
    errors: list[str] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "errors": self.errors or []}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "section"


def _hash(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _parse_front_matter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    meta: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip().lower()] = v.strip()
    return meta, text[end + 4 :].lstrip("\n")


def _split_long(text: str) -> list[str]:
    if len(text) <= MAX_CHUNK_CHARS:
        return [text]
    out: list[str] = []
    cur = ""
    for para in text.split("\n\n"):
        if cur and len(cur) + len(para) > MAX_CHUNK_CHARS:
            out.append(cur.strip())
            cur = ""
        cur += para + "\n\n"
    if cur.strip():
        out.append(cur.strip())
    return out


def load_markdown(path: Path) -> list[StoredDoc]:
    meta, body = _parse_front_matter(path.read_text(encoding="utf-8"))
    source = meta.get("source", path.parent.name or "knowledge")
    base_title = meta.get("title", path.stem.replace("_", " "))
    tags = [t.strip() for t in meta.get("tags", "").split(",") if t.strip()]
    sections = re.split(r"(?m)^## +", body)
    docs: list[StoredDoc] = []
    head = sections[0].strip()
    parts: list[tuple[str, str]] = []
    if head:
        parts.append((base_title, head))
    for sec in sections[1:]:
        title, _, rest = sec.partition("\n")
        if rest.strip():
            parts.append((title.strip(), rest.strip()))
    for title, text in parts:
        for i, piece in enumerate(_split_long(text)):
            suffix = f"-{i + 1}" if i else ""
            did = f"{path.stem}#{_slug(title)}{suffix}"
            full_title = f"{base_title}: {title}" if title != base_title else base_title
            docs.append(
                StoredDoc(
                    did,
                    source,
                    full_title,
                    piece,
                    _hash(did, full_title, piece),
                    {"file": path.name, "tags": tags},
                )
            )
    return docs


def _technique_text(t: dict[str, Any]) -> str:
    plats = ", ".join(t.get("platforms", []))
    return (
        f"{t['id']} {t['name']}. Tactic: {t['tactic']}. Platforms: {plats}.\n"
        f"{t['description']}\nDetection ideas: {t['detection']}"
    )


def load_json(path: Path) -> list[StoredDoc]:
    data = json.loads(path.read_text(encoding="utf-8"))
    source = str(data.get("source", path.stem))
    docs: list[StoredDoc] = []
    for t in data.get("techniques", []):
        did = f"mitre:{t['id']}"
        text = _technique_text(t)
        docs.append(
            StoredDoc(
                did,
                source,
                f"{t['id']} {t['name']}",
                text,
                _hash(did, text),
                {
                    "file": path.name,
                    "technique_id": t["id"],
                    "tactic": t["tactic"],
                    "attribution": "original summary",
                },
            )
        )
    for d in data.get("documents", []):
        text = str(d["text"])
        docs.append(
            StoredDoc(
                str(d["doc_id"]),
                source,
                str(d.get("title", d["doc_id"])),
                text,
                _hash(str(d["doc_id"]), text),
                {"file": path.name, **d.get("metadata", {})},
            )
        )
    return docs


def load_documents(root: Path) -> tuple[list[StoredDoc], list[str], int]:
    docs: list[StoredDoc] = []
    errors: list[str] = []
    files = 0
    for p in sorted(root.rglob("*")):
        if p.suffix not in (".md", ".json") or not p.is_file():
            continue
        files += 1
        try:
            docs.extend(load_markdown(p) if p.suffix == ".md" else load_json(p))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{p.name}: {exc}")
            log.warning("skipping %s: %s", p, exc)
    seen: set[str] = set()
    uniq: list[StoredDoc] = []
    for d in docs:
        if d.doc_id in seen:
            errors.append(f"duplicate doc_id {d.doc_id}")
            continue
        seen.add(d.doc_id)
        uniq.append(d)
    return uniq, errors, files


def ingest_directory(
    root: Path, store: VectorStore, embedder: Embedder, *, force: bool = False
) -> IngestReport:
    """Index ``root`` into ``store``. Re-fits corpus statistics (IDF) when content
    changed and re-embeds everything in that case (corpus is small)."""
    docs, errors, files = load_documents(Path(root))
    rep = IngestReport(files=files, chunks=len(docs), errors=errors)
    existing = store.hashes()
    fp_changed = store.get_meta("embedder") not in (None, embedder.fingerprint) and bool(existing)
    new_ids = {d.doc_id for d in docs}
    stale = [i for i in existing if i not in new_ids]
    changed = [d for d in docs if existing.get(d.doc_id) != d.content_hash]
    if not (force or changed or stale or fp_changed) and store.get_meta("embedder") is not None:
        rep.unchanged = len(docs)
        return rep
    # Corpus changed: refit IDF over the entire corpus and re-embed all chunks so the
    # vector space is consistent.
    embedder.fit([f"{d.title}\n{d.text}" for d in docs])
    if stale:
        store.delete(stale)
        rep.removed = len(stale)
    if docs:
        vecs = embedder.embed_batch([f"{d.title}\n{d.text}" for d in docs])
        store.upsert(docs, vecs)
    rep.added = sum(1 for d in docs if d.doc_id not in existing)
    rep.updated = len(changed) - rep.added
    rep.unchanged = len(docs) - len(changed)
    store.set_meta("embedder", embedder.fingerprint)
    store.set_meta("embedder_state", json.dumps(embedder.state()))
    store.set_meta(INDEX_VERSION_KEY, _hash(*sorted(d.content_hash for d in docs), embedder.fingerprint)[:16])
    return rep
