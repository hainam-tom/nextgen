"""Helpers for managing the product catalog JSON store."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Optional
from uuid import uuid4

from commonlib.storage import ListStore


@dataclass(slots=True)
class ProductCatalog:
    """High-level operations for the product JSON store."""

    path: str | Path
    backups: int = 2
    _store: ListStore = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._store = ListStore(self.path, backups=self.backups, recovery_label="product catalog")

    # ------------------------------------------------------------------
    # Basic CRUD operations
    # ------------------------------------------------------------------
    def all(self) -> list[dict]:
        return self._store.load()

    def create(self, payload: Dict) -> dict:
        record = dict(payload)
        record.setdefault("id", str(uuid4()))

        def mutator(items: list[dict]) -> None:
            items.append(record)

        self._store.mutate(mutator)
        return record

    def get(self, doc_id: str) -> Optional[dict]:
        target = str(doc_id)
        for item in self._store.load():
            if str(item.get("id")) == target:
                return item
        return None

    def update(self, doc_id: str, updates: Dict) -> Optional[dict]:
        target = str(doc_id)
        cleaned = {k: v for k, v in updates.items() if v is not None}
        updated: Optional[dict] = None

        def mutator(items: list[dict]) -> None:
            nonlocal updated
            for item in items:
                if str(item.get("id")) == target:
                    item.update(cleaned)
                    updated = item
                    break

        self._store.mutate(mutator)
        return updated

    def delete(self, doc_id: str) -> bool:
        target = str(doc_id)
        removed = False

        def mutator(items: list[dict]) -> Iterable[dict] | None:
            nonlocal removed
            filtered = [item for item in items if str(item.get("id")) != target]
            removed = len(filtered) != len(items)
            return filtered

        self._store.mutate(mutator)
        return removed
