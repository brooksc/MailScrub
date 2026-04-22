"""Infrastructure layer tests."""

from unittest.mock import MagicMock, patch

import pytest

from src.infrastructure.config import ConfigManager
from src.infrastructure.database import StatusRepository
from src.infrastructure.unsubscribe import UnsubscribeClient


@pytest.fixture
def tmp_config_path(tmp_path):
    return str(tmp_path / "config.json")


@pytest.fixture
def tmp_db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def tmp_config_with_db(tmp_path):
    config = ConfigManager(config_path=str(tmp_path / "config.json"))
    config.set("db_path", str(tmp_path / "test.db"))
    config.set("credentials_dir", str(tmp_path / "credentials"))
    config.set("token_dir", str(tmp_path / "tokens"))
    return config


# --- ConfigManager ---

def test_config_manager_creates_empty_config(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    assert config.get("missing") is None


def test_config_manager_set_and_get(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    config.set("key", "value")
    assert config.get("key") == "value"


def test_config_manager_default_value(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    assert config.get("missing", "default") == "default"


def test_config_manager_persists(tmp_config_path):
    config = ConfigManager(config_path=tmp_config_path)
    config.set("persistent", 42)
    config2 = ConfigManager(config_path=tmp_config_path)
    assert config2.get("persistent") == 42


# --- Database and StatusRepository ---

def test_status_repository_get_seen_domains_empty(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    assert repo.get_seen_domains() == set()


def test_status_repository_mark_and_get(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.mark_domain_seen("example.com")
    assert "example.com" in repo.get_seen_domains()


def test_status_repository_mark_idempotent(tmp_config_with_db):
    repo = StatusRepository(tmp_config_with_db)
    repo.mark_domain_seen("example.com")
    repo.mark_domain_seen("example.com")
    assert repo.get_seen_domains() == {"example.com"}


# --- UnsubscribeClient ---

def test_unsubscribe_client_process_success():
    client = UnsubscribeClient()
    with patch.object(client._session, "get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        result = client.process_unsubscribe("https://example.com/unsub")
    assert result is True


def test_unsubscribe_client_process_failure():
    client = UnsubscribeClient()
    with patch.object(client._session, "get") as mock_get:
        mock_get.return_value = MagicMock(status_code=500)
        result = client.process_unsubscribe("https://example.com/unsub")
    assert result is False


def test_unsubscribe_client_verify_always_true():
    client = UnsubscribeClient()
    assert client.verify_unsubscribe("https://example.com/unsub") is True
