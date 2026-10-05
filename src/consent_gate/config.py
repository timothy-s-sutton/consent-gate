"""Load and validate the policy configuration from config/*.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

from consent_gate.models import PolicyConfig

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "larkspur.db"


def load_policy_config(config_dir: Path = CONFIG_DIR) -> PolicyConfig:
    """Read purposes.yaml and roles.yaml. Raises if anything is missing or invalid."""
    merged: dict = {}
    for name in ("purposes.yaml", "roles.yaml"):
        data = yaml.safe_load((config_dir / name).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{name}: expected a mapping at the top level")
        overlap = merged.keys() & data.keys()
        if overlap:
            raise ValueError(f"{name}: duplicate top-level keys {sorted(overlap)}")
        merged.update(data)
    return PolicyConfig.model_validate(merged)
