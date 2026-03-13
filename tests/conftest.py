"""Shared test fixtures for cloud-audit."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

    from cloud_audit.providers.gcp.provider import GCPProvider


@pytest.fixture()
def mock_gcp_provider(monkeypatch: pytest.MonkeyPatch) -> Generator[GCPProvider, None, None]:
    """Create a mocked GCPProvider."""
    # Patch default credentials to avoid actual GCP auth during tests
    monkeypatch.setattr("google.auth.default", lambda: (MagicMock(), "my-gcp-project"))

    from cloud_audit.providers.gcp.provider import GCPProvider

    provider = GCPProvider(project="my-gcp-project")

    # We could also mock the get_client to return a MagicMock here if we wanted
    # to do more extensive unit testing of checks in the future.
    provider.get_client = MagicMock()

    yield provider
