"""Tests for perimtr.core.exceptions."""

import pytest
from perimtr.core.exceptions import (
    ConfigError,
    DataStoreError,
    LLMError,
    ModuleError,
    NetworkError,
    PerimtrError,
    ScanTimeoutError,
    TargetValidationError,
)


# ---------------------------------------------------------------------------
# Instantiation tests
# ---------------------------------------------------------------------------

class TestPerimtrError:
    def test_basic(self):
        exc = PerimtrError("base error")
        assert str(exc) == "base error"

    def test_is_exception(self):
        assert issubclass(PerimtrError, Exception)


class TestConfigError:
    def test_message_only(self):
        exc = ConfigError("bad config")
        assert str(exc) == "bad config"
        assert exc.field is None
        assert exc.value is None

    def test_with_field(self):
        exc = ConfigError("invalid", field="timeout")
        assert exc.field == "timeout"
        assert exc.value is None

    def test_with_field_and_value(self):
        exc = ConfigError("invalid", field="port", value=-1)
        assert exc.field == "port"
        assert exc.value == -1

    def test_inherits_perimtr_error(self):
        exc = ConfigError("x")
        assert isinstance(exc, PerimtrError)


class TestModuleError:
    def test_message_only(self):
        exc = ModuleError("module failed")
        assert str(exc) == "module failed"
        assert exc.module_name is None

    def test_with_module_name(self):
        exc = ModuleError("failed", module_name="port_scanner")
        assert exc.module_name == "port_scanner"

    def test_inherits_perimtr_error(self):
        exc = ModuleError("x")
        assert isinstance(exc, PerimtrError)


class TestTargetValidationError:
    def test_basic(self):
        exc = TargetValidationError("bad target")
        assert str(exc) == "bad target"

    def test_with_field_and_value(self):
        exc = TargetValidationError("bad domain", field="domains", value="not_a_domain")
        assert exc.field == "domains"
        assert exc.value == "not_a_domain"

    def test_inherits_config_error(self):
        exc = TargetValidationError("x")
        assert isinstance(exc, ConfigError)

    def test_inherits_perimtr_error(self):
        exc = TargetValidationError("x")
        assert isinstance(exc, PerimtrError)


class TestDataStoreError:
    def test_basic(self):
        exc = DataStoreError("write failed")
        assert str(exc) == "write failed"

    def test_inherits_perimtr_error(self):
        exc = DataStoreError("x")
        assert isinstance(exc, PerimtrError)


class TestLLMError:
    def test_message_only(self):
        exc = LLMError("llm failed")
        assert str(exc) == "llm failed"
        assert exc.provider is None
        assert exc.status_code is None

    def test_with_provider(self):
        exc = LLMError("rate limited", provider="openai")
        assert exc.provider == "openai"

    def test_with_status_code(self):
        exc = LLMError("auth error", provider="anthropic", status_code=401)
        assert exc.status_code == 401
        assert exc.provider == "anthropic"

    def test_inherits_perimtr_error(self):
        exc = LLMError("x")
        assert isinstance(exc, PerimtrError)


class TestScanTimeoutError:
    def test_basic(self):
        exc = ScanTimeoutError("timed out")
        assert str(exc) == "timed out"

    def test_with_module_name(self):
        exc = ScanTimeoutError("timeout", module_name="dns_enum")
        assert exc.module_name == "dns_enum"

    def test_inherits_module_error(self):
        exc = ScanTimeoutError("x")
        assert isinstance(exc, ModuleError)

    def test_inherits_perimtr_error(self):
        exc = ScanTimeoutError("x")
        assert isinstance(exc, PerimtrError)


class TestNetworkError:
    def test_basic(self):
        exc = NetworkError("connection refused")
        assert str(exc) == "connection refused"

    def test_inherits_perimtr_error(self):
        exc = NetworkError("x")
        assert isinstance(exc, PerimtrError)


# ---------------------------------------------------------------------------
# Raising / catching tests
# ---------------------------------------------------------------------------

class TestExceptionRaising:
    def test_raise_and_catch_as_base(self):
        with pytest.raises(PerimtrError):
            raise ConfigError("oops")

    def test_raise_scan_timeout_caught_as_module_error(self):
        with pytest.raises(ModuleError):
            raise ScanTimeoutError("slow", module_name="port_scanner")

    def test_raise_target_validation_caught_as_config_error(self):
        with pytest.raises(ConfigError):
            raise TargetValidationError("bad", field="cidrs")

    def test_llm_error_not_caught_as_module_error(self):
        """LLMError should NOT match ModuleError."""
        with pytest.raises(LLMError):
            try:
                raise LLMError("fail")
            except ModuleError:
                pass  # should NOT enter here
            raise LLMError("fail")  # should reach here

    def test_all_inherit_from_perimtr_error(self):
        exception_types = [
            ConfigError,
            ModuleError,
            TargetValidationError,
            DataStoreError,
            LLMError,
            ScanTimeoutError,
            NetworkError,
        ]
        for exc_type in exception_types:
            assert issubclass(exc_type, PerimtrError), (
                f"{exc_type.__name__} does not inherit from PerimtrError"
            )
