import os
from dataclasses import dataclass, field

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Config:
    ignore_paths: list[str] = field(default_factory=list)
    disable_scanners: list[str] = field(default_factory=list)
    min_severity: str = "LOW"

    _SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    def should_skip_path(self, rel_path: str) -> bool:
        normalized = rel_path.replace("\\", "/")
        for pattern in self.ignore_paths:
            if pattern in normalized:
                return True
        return False

    def is_scanner_enabled(self, category: str) -> bool:
        return category not in self.disable_scanners

    def passes_severity(self, severity: str) -> bool:
        threshold = self._SEVERITY_ORDER.get(self.min_severity.upper(), 2)
        finding_level = self._SEVERITY_ORDER.get(severity.upper(), 2)
        return finding_level <= threshold


def load_config(target: str) -> Config:
    for name in (".ragguard.toml", "ragguard.toml"):
        path = os.path.join(target, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                data = tomllib.load(f)
            section = data.get("ragguard", data)
            return Config(
                ignore_paths=section.get("ignore_paths", []),
                disable_scanners=section.get("disable_scanners", []),
                min_severity=section.get("min_severity", "LOW"),
            )
    return Config()
