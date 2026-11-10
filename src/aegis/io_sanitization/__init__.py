"""Hidden-context redaction and downstream sink sanitisation."""

from aegis.io_sanitization.dlp import DlpRedactor, ReasoningMode, RedactionResult
from aegis.io_sanitization.sinks import (
    PackageAllowlist,
    ShellPolicy,
    SinkVerdict,
    SqlPolicy,
    extract_package_recommendations,
    strip_untrusted_images,
    validate_shell_command,
    validate_sql,
)

__all__ = [
    "DlpRedactor",
    "PackageAllowlist",
    "ReasoningMode",
    "RedactionResult",
    "ShellPolicy",
    "SinkVerdict",
    "SqlPolicy",
    "extract_package_recommendations",
    "strip_untrusted_images",
    "validate_shell_command",
    "validate_sql",
]
