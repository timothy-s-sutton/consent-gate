"""Offline TF-IDF retrieval over the Larkspur policy documents in policies/*.md.

Documents are split into chunks at ## and ### headings. Each result carries its
source file and heading path so the agent can cite it. No customer data is
involved and nothing leaves the machine.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer

from consent_gate.config import PROJECT_ROOT
from consent_gate.models import PolicyChunk, PolicyHit

POLICIES_DIR = PROJECT_ROOT / "policies"

_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*$")


def chunk_markdown(source: str, markdown: str) -> list[PolicyChunk]:
    """Split a markdown document into chunks at #, ##, and ### headings."""
    chunks: list[PolicyChunk] = []
    title = source
    section: str | None = None
    heading = source
    lines: list[str] = []

    def flush() -> None:
        text = "\n".join(lines).strip()
        if text:
            chunks.append(PolicyChunk(source=source, heading=heading, text=text))
        lines.clear()

    for line in markdown.splitlines():
        m = _HEADING.match(line)
        if not m:
            lines.append(line)
            continue
        flush()
        level, name = len(m.group(1)), m.group(2)
        if level == 1:
            title = heading = name
            section = None
        elif level == 2:
            section = name
            heading = f"{title} > {name}"
        else:
            heading = f"{title} > {section} > {name}" if section else f"{title} > {name}"
    flush()
    return chunks


class PolicyIndex:
    def __init__(self, chunks: Sequence[PolicyChunk]) -> None:
        if not chunks:
            raise ValueError("no policy chunks to index")
        self.chunks = list(chunks)
        self._vectorizer = TfidfVectorizer(
            stop_words="english", ngram_range=(1, 2), sublinear_tf=True
        )
        # Headings are indexed with the body, so a section title is a strong signal.
        self._matrix = self._vectorizer.fit_transform(f"{c.heading}\n{c.text}" for c in self.chunks)

    @classmethod
    def from_directory(cls, directory: Path = POLICIES_DIR) -> PolicyIndex:
        chunks: list[PolicyChunk] = []
        for path in sorted(Path(directory).glob("*.md")):
            chunks += chunk_markdown(path.name, path.read_text(encoding="utf-8"))
        return cls(chunks)

    def search(self, question: str, k: int) -> list[PolicyHit]:
        """Top-k chunks by cosine similarity. Chunks with no overlap are never returned."""
        query = self._vectorizer.transform([question])
        scores = (self._matrix @ query.T).toarray().ravel()  # rows are L2-normalized
        ranked = sorted(range(len(scores)), key=lambda i: (-scores[i], i))
        return [
            PolicyHit(**self.chunks[i].model_dump(), score=round(float(scores[i]), 4))
            for i in ranked[:k]
            if scores[i] > 0
        ]
