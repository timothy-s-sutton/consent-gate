"""Read-only access to the Larkspur customer database.

Connections are opened read-only (SQLite URI mode=ro plus PRAGMA query_only), one
per call, because MCP sync tool handlers run on worker threads.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path

from consent_gate.models import ConsentRecord, Customer


class CustomerStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file():
            raise FileNotFoundError("customer database not found")
        uri = self.path.resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            yield conn

    def get_customer(self, customer_id: str) -> Customer | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
        return Customer(**dict(row)) if row else None

    def search(
        self,
        state: str | None = None,
        segment: str | None = None,
        name_contains: str | None = None,
    ) -> list[Customer]:
        """All customers matching the filters, ordered by id. Filters are parameterized."""
        clauses: list[str] = []
        params: list[str] = []
        if state is not None:
            clauses.append("state = ?")
            params.append(state)
        if segment is not None:
            clauses.append("segment = ?")
            params.append(segment)
        if name_contains is not None:
            # instr() rather than LIKE, so % and _ in the input are literal.
            clauses.append("instr(lower(full_name), lower(?)) > 0")
            params.append(name_contains)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM customers{where} ORDER BY customer_id"  # noqa: S608 -- fixed clauses, values bound
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [Customer(**dict(r)) for r in rows]

    def consents_for(self, customer_ids: Sequence[str]) -> dict[str, list[ConsentRecord]]:
        result: dict[str, list[ConsentRecord]] = {cid: [] for cid in customer_ids}
        if not customer_ids:
            return result
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM consents WHERE customer_id IN (SELECT value FROM json_each(?))",
                (json.dumps(list(customer_ids)),),
            ).fetchall()
        for r in rows:
            result[r["customer_id"]].append(ConsentRecord(**dict(r)))
        return result
