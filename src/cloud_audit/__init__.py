"""gcp-auditor - Scan your GCP infrastructure for security, compliance, and reliability issues."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("gcp-auditor")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
