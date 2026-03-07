"""GCP provider implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import google.auth
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from googleapiclient import discovery

from cloud_audit.providers.base import BaseProvider
from cloud_audit.providers.gcp.checks import (
    bigquery,
    cloudsql,
    compute,
    firewall,
    gke,
    iam,
    kms,
    logging_,
    storage,
)

if TYPE_CHECKING:
    from cloud_audit.providers.base import CheckFn

# Registry of all GCP checks, grouped by service
_CHECK_MODULES = [
    iam,
    storage,
    compute,
    firewall,
    cloudsql,
    kms,
    logging_,
    bigquery,
    gke,
]


class GCPProvider(BaseProvider):
    """Google Cloud Platform provider - uses google-cloud SDK to scan resources."""

    def __init__(
        self,
        project: str | None = None,
        regions: list[str] | None = None,
        service_account_key: str | None = None,
    ) -> None:
        if service_account_key:
            self._credentials = service_account.Credentials.from_service_account_file(
                service_account_key,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            self._project = project or self._credentials.project_id
        else:
            self._credentials, detected_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
            self._project = project or detected_project

        if not self._project:
            msg = (
                "Could not determine GCP project. "
                "Set --project flag, GOOGLE_CLOUD_PROJECT env var, or use a service account key."
            )
            raise ValueError(msg)

        # Ensure credentials are valid
        if hasattr(self._credentials, "refresh"):
            self._credentials.refresh(Request())

        self._regions = regions or ["us-central1", "us-east1", "europe-west1"]

        # Build API clients (cached)
        self._crm_service = discovery.build("cloudresourcemanager", "v1", credentials=self._credentials)
        self._compute_service = discovery.build("compute", "v1", credentials=self._credentials)
        self._iam_service = discovery.build("iam", "v1", credentials=self._credentials)
        self._storage_client = None  # Lazy init (uses google-cloud-storage)
        self._logging_service = discovery.build("logging", "v2", credentials=self._credentials)
        self._sqladmin_service = discovery.build("sqladmin", "v1beta4", credentials=self._credentials)
        self._kms_service = discovery.build("cloudkms", "v1", credentials=self._credentials)
        self._bigquery_service = discovery.build("bigquery", "v2", credentials=self._credentials)
        self._container_service = discovery.build("container", "v1", credentials=self._credentials)

    @property
    def project(self) -> str:
        return self._project

    @property
    def credentials(self) -> google.auth.credentials.Credentials:
        return self._credentials

    @property
    def regions(self) -> list[str]:
        return self._regions

    @property
    def compute_service(self) -> discovery.Resource:
        return self._compute_service

    @property
    def iam_service(self) -> discovery.Resource:
        return self._iam_service

    @property
    def crm_service(self) -> discovery.Resource:
        return self._crm_service

    @property
    def storage_client(self):  # noqa: ANN201
        """Lazy-init google.cloud.storage client."""
        if self._storage_client is None:
            from google.cloud import storage

            self._storage_client = storage.Client(project=self._project, credentials=self._credentials)
        return self._storage_client

    @property
    def logging_service(self) -> discovery.Resource:
        return self._logging_service

    @property
    def sqladmin_service(self) -> discovery.Resource:
        return self._sqladmin_service

    @property
    def kms_service(self) -> discovery.Resource:
        return self._kms_service

    @property
    def bigquery_service(self) -> discovery.Resource:
        return self._bigquery_service

    @property
    def container_service(self) -> discovery.Resource:
        return self._container_service

    def get_account_id(self) -> str:
        return self._project

    def get_provider_name(self) -> str:
        return "gcp"

    def get_checks(self, categories: list[str] | None = None) -> list[CheckFn]:
        checks: list[CheckFn] = []
        for module in _CHECK_MODULES:
            for check_fn in module.get_checks(self):
                if categories:
                    check_category = getattr(check_fn, "category", None)
                    if check_category and check_category not in categories:
                        continue
                checks.append(check_fn)
        return checks
