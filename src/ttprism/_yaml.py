"""Safe loading of user-supplied YAML (rules and allowlists)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.nodes import Node

MAX_CONFIG_BYTES = 2 * 1024 * 1024


class ConfigError(ValueError):
    """A rule or allowlist file is missing, too large, or malformed."""


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that rejects aliases.

    An alias repeats a whole subtree, so a small file could expand into millions
    of rule phrases (lists of lists of strings are valid in rule files).
    """

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(yaml.AliasEvent):  # check_event stores the event in current_event
            raise ComposerError(None, None, "YAML aliases are not allowed", self.current_event.start_mark)
        return super().compose_node(parent, index)


def load_yaml_text(text: str, where: str, error: type[ConfigError] = ConfigError) -> Any:
    try:
        # A SafeLoader only builds plain scalars, lists and dicts: no object construction.
        return yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506
    except yaml.YAMLError as exc:
        raise error(f"{where}: invalid YAML: {exc}") from None
    except RecursionError:
        # PyYAML composes nested collections recursively.
        raise error(f"{where}: YAML nesting too deep") from None


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
