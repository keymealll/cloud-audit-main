"""Google Cloud Platform (GCP) Provider."""

from __future__ import annotations

import collections
import importlib
import inspect
import pkgutil
from typing import Callable, Optional

from google.auth import default
from googleapiclient.discovery import build

from cloud_audit.models import CheckResult
from cloud_audit.providers.base import BaseProvider


class GCPProvider(BaseProvider):
    """Provides GCP clients and discovers implemented GCP checks."""

    def __init__(self, project: Optional[str] = None) -> None:
        """Initialize GCP provider."""
        self.credentials, self._default_project = default()
        self.project_id = project or self._default_project
        if not self.project_id:
            raise ValueError(
                "Could not determine GCP project. Set it via --project or GOOGLE_CLOUD_PROJECT environment variable."
            )

        self.services: dict[str, object] = {}

    def get_provider_name(self) -> str:
        return "gcp"

    def get_account_id(self) -> str:
        return self.project_id

    def get_client(self, service_name: str, version: str = "v1") -> object:
        """Get or create a cached GCP API client."""
        key = f"{service_name}_{version}"
        if key not in self.services:
            self.services[key] = build(service_name, version, credentials=self.credentials, cache_discovery=False)
        return self.services[key]

    def get_checks(self, categories: Optional[list[str]] = None) -> list[Callable[[], CheckResult]]:
        """Discover all check functions inside cloud_audit.providers.gcp.checks.*."""
        import cloud_audit.providers.gcp.checks as checks_pkg

        checks = []
        for _, module_name, _ in pkgutil.iter_modules(checks_pkg.__path__):
            module = importlib.import_module(f"cloud_audit.providers.gcp.checks.{module_name}")
            for name, obj in inspect.getmembers(module):
                if inspect.isfunction(obj) and getattr(obj, "__module__", "") == module.__name__:
                    if not name.startswith("_"):
                        # If categories filter is applied
                        # We would filter by fn.category but right now keep simple
                        def wrapper(self=self, fn=obj):
                            return fn(self)
                        
                        wrapper.__name__ = name
                        checks.append(wrapper)

        return checks
