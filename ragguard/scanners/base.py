from abc import ABC, abstractmethod

from ragguard.finding import Finding


class BaseScanner(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def category(self) -> str: ...

    @abstractmethod
    def scan_file(self, file_path: str, content: str, lines: list[str]) -> list[Finding]: ...
