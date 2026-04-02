"""Base connector interface for all forensic data sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):
    """Abstract base for all forensic data source connectors."""

    @abstractmethod
    def connect(self, path: str, **kwargs: Any) -> dict:
        """Open a connection to the data source. Returns metadata dict.
        Must NOT bulk-load data — only establish connection and cache lookups.
        """
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Close the connection and release resources."""
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        ...

    @abstractmethod
    def get_metadata(self) -> dict:
        """Return source metadata."""
        ...

    @abstractmethod
    def search(self, keyword: str = "", filters: dict | None = None,
               limit: int = 50, offset: int = 0) -> dict:
        """Generic search. Each connector defines its own filter keys."""
        ...

    def get_capabilities(self) -> list[str]:
        """Return list of capability strings this connector supports."""
        return ["search"]
