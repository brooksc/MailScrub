"""Tests for MailScrub entry-point functions."""

import importlib.machinery
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Load the MailScrub script (no .py extension) as a module
_SCRIPT = str(Path(__file__).parent.parent / "MailScrub")
_loader = importlib.machinery.SourceFileLoader("mailscrub_entrypoint", _SCRIPT)
_spec = importlib.util.spec_from_loader("mailscrub_entrypoint", _loader)
_mod = importlib.util.module_from_spec(_spec)
_loader.exec_module(_mod)

_maybe_migrate_legacy = _mod._maybe_migrate_legacy
_pick_account = _mod._pick_account
_resolve_user = _mod._resolve_user


# ---------------------------------------------------------------------------
# _maybe_migrate_legacy
# ---------------------------------------------------------------------------

def test_maybe_migrate_skips_when_accounts_exist(tmp_path):
    """If accounts are already registered, migration is a no-op."""
    from src.infrastructure.config import ConfigManager
    cfg = ConfigManager(config_path=str(tmp_path / "cfg.json"))
    cfg.add_account("a@example.com")

    with patch.object(_mod, "console") as mock_console:
        _maybe_migrate_legacy(cfg)
        mock_console.print.assert_not_called()


def test_maybe_migrate_skips_when_no_legacy_token(tmp_path):
    """If token.json does not exist, migration is a no-op."""
    from src.infrastructure.config import ConfigManager
    cfg = ConfigManager(config_path=str(tmp_path / "cfg.json"))
    # No accounts registered, but also no legacy token on disk
    with (
        patch("src.infrastructure.config._BASE_DIR", tmp_path),
        patch.object(_mod, "console"),
    ):
        _maybe_migrate_legacy(cfg)
        assert cfg.get_accounts() == {}


def test_maybe_migrate_happy_path(tmp_path):
    """Legacy token exists → files renamed, account added to config."""
    from src.infrastructure.config import ConfigManager

    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    legacy_token = token_dir / "token.json"
    legacy_token.write_text("{}")

    legacy_db = tmp_path / "mailscrub.db"
    legacy_db.write_bytes(b"")

    cfg = ConfigManager(config_path=str(tmp_path / "cfg.json"))

    mock_repo = MagicMock()
    mock_repo.get_primary_email.return_value = "user@gmail.com"

    with (
        patch("src.infrastructure.config._BASE_DIR", tmp_path),
        patch("src.infrastructure.gmail.GmailRepository", return_value=mock_repo),
        patch.object(_mod, "console"),
    ):
        _maybe_migrate_legacy(cfg)

    assert (token_dir / "user@gmail.com.json").exists()
    assert not legacy_token.exists()
    assert (tmp_path / "user@gmail.com.db").exists()
    assert not legacy_db.exists()
    assert "user@gmail.com" in cfg.get_accounts()


def test_maybe_migrate_exception_does_not_crash(tmp_path):
    """Exception during migration is caught; no crash."""
    from src.infrastructure.config import ConfigManager

    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    (token_dir / "token.json").write_text("{}")

    cfg = ConfigManager(config_path=str(tmp_path / "cfg.json"))

    mock_repo = MagicMock()
    mock_repo._initialize_service.side_effect = Exception("auth failure")

    with (
        patch("src.infrastructure.config._BASE_DIR", tmp_path),
        patch("src.infrastructure.gmail.GmailRepository", return_value=mock_repo),
        patch.object(_mod, "console"),
    ):
        _maybe_migrate_legacy(cfg)  # must not raise

    assert cfg.get_accounts() == {}


# ---------------------------------------------------------------------------
# _pick_account
# ---------------------------------------------------------------------------

def test_pick_account_valid_selection():
    accounts = {"a@example.com": {}, "b@example.com": {"is_default": True}}
    with (
        patch.object(_mod, "console") as mock_console,
    ):
        mock_console.input.return_value = "1"
        result = _pick_account(accounts)
    assert result == "a@example.com"


def test_pick_account_selects_second():
    accounts = {"a@example.com": {}, "b@example.com": {}}
    with patch.object(_mod, "console") as mock_console:
        mock_console.input.return_value = "2"
        result = _pick_account(accounts)
    assert result == "b@example.com"


def test_pick_account_q_exits():
    accounts = {"a@example.com": {}}
    with patch.object(_mod, "console") as mock_console:
        mock_console.input.return_value = "q"
        with pytest.raises(SystemExit) as exc_info:
            _pick_account(accounts)
    assert exc_info.value.code == 0


def test_pick_account_eof_exits():
    accounts = {"a@example.com": {}}
    with patch.object(_mod, "console") as mock_console:
        mock_console.input.side_effect = EOFError
        with pytest.raises(SystemExit) as exc_info:
            _pick_account(accounts)
    assert exc_info.value.code == 0


def test_pick_account_invalid_then_valid():
    """Out-of-range input loops until valid entry."""
    accounts = {"a@example.com": {}}
    inputs = iter(["99", "abc", "1"])
    with patch.object(_mod, "console") as mock_console:
        mock_console.input.side_effect = lambda _: next(inputs)
        result = _pick_account(accounts)
    assert result == "a@example.com"


# ---------------------------------------------------------------------------
# _resolve_user
# ---------------------------------------------------------------------------

def _cfg(tmp_path, accounts=None):
    from src.infrastructure.config import ConfigManager
    cfg = ConfigManager(config_path=str(tmp_path / "cfg.json"))
    for email in (accounts or []):
        cfg.add_account(email)
    return cfg


def test_resolve_user_new_flag_returns_none(tmp_path):
    cfg = _cfg(tmp_path)
    result = _resolve_user(args_user=None, args_new=True, cfg=cfg)
    assert result is None


def test_resolve_user_explicit_user_returned(tmp_path):
    cfg = _cfg(tmp_path, ["me@gmail.com"])
    result = _resolve_user(args_user="me@gmail.com", args_new=False, cfg=cfg)
    assert result == "me@gmail.com"


def test_resolve_user_unknown_account_exits(tmp_path):
    cfg = _cfg(tmp_path, ["a@gmail.com"])
    with patch.object(_mod, "console"):
        with pytest.raises(SystemExit) as exc_info:
            _resolve_user(args_user="unknown@gmail.com", args_new=False, cfg=cfg)
    assert exc_info.value.code == 1


def test_resolve_user_no_accounts_returns_default(tmp_path):
    """No registered accounts → returns None (legacy single-account mode)."""
    cfg = _cfg(tmp_path)
    result = _resolve_user(args_user=None, args_new=False, cfg=cfg)
    assert result is None


def test_resolve_user_single_account_returns_default(tmp_path):
    cfg = _cfg(tmp_path, ["only@gmail.com"])
    result = _resolve_user(args_user=None, args_new=False, cfg=cfg)
    assert result == "only@gmail.com"


def test_resolve_user_multiple_accounts_calls_pick(tmp_path):
    """Multiple accounts → delegates to _pick_account."""
    cfg = _cfg(tmp_path, ["a@gmail.com", "b@gmail.com"])
    with patch.object(_mod, "_pick_account", return_value="b@gmail.com") as mock_pick:
        result = _resolve_user(args_user=None, args_new=False, cfg=cfg)
    assert result == "b@gmail.com"
    mock_pick.assert_called_once()
