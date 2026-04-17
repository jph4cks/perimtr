"""
Custom exceptions for Perimtr.

Provides a hierarchy of exceptions for clear error handling
across the application.
"""


class PerimtrError(Exception):
    """Base exception for all Perimtr errors."""
    pass


class ConfigError(PerimtrError):
    """Configuration validation or loading error.

    Attributes:
        field: The config field that caused the error, if applicable.
        value: The invalid value, if applicable.
    """

    def __init__(self, message: str, field: str = None, value=None):
        self.field = field
        self.value = value
        super().__init__(message)


class ModuleError(PerimtrError):
    """Error during module execution."""

    def __init__(self, message: str, module_name: str = None):
        self.module_name = module_name
        super().__init__(message)


class TargetValidationError(ConfigError):
    """Invalid target specification (bad CIDR, invalid domain)."""
    pass


class DataStoreError(PerimtrError):
    """Error reading/writing assessment data."""
    pass


class LLMError(PerimtrError):
    """Error communicating with LLM provider."""

    def __init__(self, message: str, provider: str = None, status_code: int = None):
        self.provider = provider
        self.status_code = status_code
        super().__init__(message)


class ScanTimeoutError(ModuleError):
    """A scan module exceeded its time limit."""
    pass


class NetworkError(PerimtrError):
    """Network connectivity error during scanning."""
    pass
