"""Safe loading of user-supplied YAML (rules and allowlists)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

MAX_CONFIG_BYTES = 2 * 1024 * 1024


class ConfigError(ValueError):
    """A rule or allowlist file is missing, too large, or malformed."""


def load_yaml_text(text: str, where: str, error: type[ConfigError] = ConfigError) -> Any:
    try:
        # safe_load only builds plain scalars, lists and dicts: no object construction.
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise error(f"{where}: invalid YAML: {exc}") from None


def load_yaml_file(path: str | Path, error: type[ConfigError] = ConfigError) -> Any:
    path = Path(path)
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise error(f"{path}: cannot read: {exc.strerror or exc}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise error(f"{path}: larger than {MAX_CONFIG_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise error(f"{path}: not valid UTF-8") from None
    return load_yaml_text(text, str(path), error)
