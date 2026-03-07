"""Tests for config file parser."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from cloud_audit.config import Suppression, load_config


def _write_yaml(tmp_path: Path, content: str) -> Path:
    """Write YAML content to a temp file and return the path."""
    p = tmp_path / ".gcp-auditor.yml"
    p.write_text(content, encoding="utf-8")
    return p


def test_load_default_when_no_file(tmp_path: Path) -> None:
    """No config file -> default config."""
    config = load_config(tmp_path / "nonexistent.yml")
    assert config.provider == "aws"
    assert config.profile is None
    assert config.regions is None
    assert config.min_severity is None
    assert config.exclude_checks == []
    assert config.suppressions == []


def test_load_valid_config(tmp_path: Path) -> None:
    """Full valid config is parsed correctly."""
    p = _write_yaml(
        tmp_path,
        """
provider: aws
profile: production
regions:
  - eu-central-1
  - eu-west-1
min_severity: medium
exclude_checks:
  - aws-ec2-003
  - aws-eip-001
suppressions:
  - check_id: aws-vpc-002
    resource_id: sg-0abc123
    reason: "VPN gateway"
    accepted_by: mariusz
    expires: "2026-09-01"
""",
    )
    config = load_config(p)
    assert config.provider == "aws"
    assert config.profile == "production"
    assert config.regions == ["eu-central-1", "eu-west-1"]
    assert config.min_severity is not None
    assert config.min_severity.value == "medium"
    assert config.exclude_checks == ["aws-ec2-003", "aws-eip-001"]
    assert len(config.suppressions) == 1
    assert config.suppressions[0].check_id == "aws-vpc-002"
    assert config.suppressions[0].resource_id == "sg-0abc123"
    assert config.suppressions[0].reason == "VPN gateway"
    assert config.suppressions[0].accepted_by == "mariusz"
    assert config.suppressions[0].expires == date(2026, 9, 1)


def test_load_minimal_config(tmp_path: Path) -> None:
    """Config with only provider."""
    p = _write_yaml(tmp_path, "provider: aws\n")
    config = load_config(p)
    assert config.provider == "aws"
    assert config.suppressions == []


def test_load_unknown_keys_raises(tmp_path: Path) -> None:
    """Unknown keys in YAML raise ValueError."""
    p = _write_yaml(tmp_path, "provider: aws\nfoo: bar\n")
    with pytest.raises(ValueError, match="Unknown keys"):
        load_config(p)


def test_load_invalid_severity_raises(tmp_path: Path) -> None:
    """Invalid severity value raises validation error."""
    p = _write_yaml(tmp_path, "min_severity: ultra_mega\n")
    with pytest.raises(ValidationError):
        load_config(p)


def test_load_invalid_yaml_raises(tmp_path: Path) -> None:
    """Malformed YAML raises ValueError with helpful message."""
    p = _write_yaml(tmp_path, "provider: aws\n  regions:\n    - eu-central-1\n")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_config(p)


def test_load_empty_yaml(tmp_path: Path) -> None:
    """Empty YAML file -> default config."""
    p = _write_yaml(tmp_path, "")
    config = load_config(p)
    assert config.provider == "aws"


def test_load_severity_case_insensitive(tmp_path: Path) -> None:
    """Severity parsing is case-insensitive."""
    p = _write_yaml(tmp_path, "min_severity: HIGH\n")
    config = load_config(p)
    assert config.min_severity is not None
    assert config.min_severity.value == "high"


def test_suppression_no_resource_id(tmp_path: Path) -> None:
    """Suppression without resource_id suppresses entire check."""
    p = _write_yaml(
        tmp_path,
        """
suppressions:
  - check_id: aws-ec2-003
    reason: "All stopped instances are OK"
""",
    )
    config = load_config(p)
    assert len(config.suppressions) == 1
    assert config.suppressions[0].resource_id is None


# --- Suppression model tests ---


def test_suppression_matches_exact() -> None:
    s = Suppression(check_id="aws-iam-001", resource_id="root", reason="OK")
    assert s.matches("aws-iam-001", "root")
    assert not s.matches("aws-iam-001", "other-user")
    assert not s.matches("aws-iam-002", "root")


def test_suppression_matches_no_resource_id() -> None:
    """No resource_id = match any resource for that check."""
    s = Suppression(check_id="aws-ec2-003", reason="All stopped OK")
    assert s.matches("aws-ec2-003", "i-12345")
    assert s.matches("aws-ec2-003", "i-99999")
    assert not s.matches("aws-ec2-004", "i-12345")


def test_suppression_is_expired() -> None:
    s = Suppression(check_id="aws-iam-001", reason="OK", expires=date(2026, 1, 1))
    assert s.is_expired(today=date(2026, 3, 5))
    assert not s.is_expired(today=date(2025, 12, 31))


def test_suppression_no_expiry_never_expired() -> None:
    s = Suppression(check_id="aws-iam-001", reason="OK")
    assert not s.is_expired(today=date(2099, 12, 31))


def test_load_auto_detects_from_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """load_config(None) finds .gcp-auditor.yml in the current directory."""
    _write_yaml(tmp_path, "provider: aws\nmin_severity: high\n")
    monkeypatch.chdir(tmp_path)
    config = load_config()
    assert config.min_severity is not None
    assert config.min_severity.value == "high"
