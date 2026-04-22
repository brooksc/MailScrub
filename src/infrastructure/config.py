"""Configuration management implementation."""

import json
import os
from pathlib import Path
from typing import Any

from ..domain.exceptions import ConfigurationError

_BASE_DIR = Path.home() / ".config" / "mailscrub"


class ConfigManager:
    """Manages application configuration with optional per-user path isolation."""

    def __init__(self, config_path: str | None = None, user: str | None = None):
        self.config: dict[str, Any] = {}
        self.user = user
        self.config_path = config_path or self._default_config_path()
        self._load_config()

    def _default_config_path(self) -> str:
        old_path = Path.home() / ".mailscrub" / "config.json"
        if not _BASE_DIR.exists() and old_path.exists():
            import shutil
            _BASE_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copytree(str(old_path.parent), str(_BASE_DIR), dirs_exist_ok=True)
        return str(_BASE_DIR / "config.json")

    def _load_config(self) -> None:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path) as f:
                    self.config = json.load(f)
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {str(e)}")

    def _save_config(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            raise ConfigurationError(f"Failed to save config: {str(e)}")

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.config[key] = value
        self._save_config()

    def delete(self, key: str) -> None:
        if key in self.config:
            del self.config[key]
            self._save_config()

    # ------------------------------------------------------------------
    # Account registry
    # ------------------------------------------------------------------

    def get_accounts(self) -> dict[str, dict]:
        """Return registered accounts: {email: {is_default: bool}}."""
        return self.config.get("accounts", {})

    def get_default_account(self) -> str | None:
        """Return the email of the default account, or None if none registered."""
        for email, meta in self.get_accounts().items():
            if meta.get("is_default"):
                return email
        accounts = self.get_accounts()
        return next(iter(accounts), None) if len(accounts) == 1 else None

    def add_account(self, email: str, set_default: bool = False) -> None:
        """Register an account. If it's the first account, make it default."""
        accounts = self.get_accounts()
        is_first = len(accounts) == 0
        accounts[email] = {"is_default": is_first or set_default}
        if set_default:
            for other in accounts:
                if other != email:
                    accounts[other]["is_default"] = False
        self.config["accounts"] = accounts
        self._save_config()

    def set_default_account(self, email: str) -> None:
        accounts = self.get_accounts()
        for e in accounts:
            accounts[e]["is_default"] = e == email
        self.config["accounts"] = accounts
        self._save_config()

    def resolve_user(self, user: str | None) -> str | None:
        """Return the effective account email: explicit > default > None (legacy)."""
        if user:
            return user
        return self.get_default_account()

    # ------------------------------------------------------------------
    # Paths (per-user when self.user is set, legacy otherwise)
    # ------------------------------------------------------------------

    def get_credentials_dir(self) -> str:
        creds_dir = self.get("credentials_dir")
        if not creds_dir:
            creds_dir = str(_BASE_DIR / "credentials")
            self.set("credentials_dir", creds_dir)
        return creds_dir

    def get_credentials_path(self) -> str:
        return str(Path(self.get_credentials_dir()) / "credentials.json")

    def get_token_dir(self) -> str:
        token_dir = self.get("token_dir")
        if not token_dir:
            token_dir = str(_BASE_DIR / "tokens")
            self.set("token_dir", token_dir)
        return token_dir

    def get_token_path(self) -> str:
        token_dir = self.get_token_dir()
        if self.user:
            return str(Path(token_dir) / f"{self.user}.json")
        return str(Path(token_dir) / "token.json")

    def get_db_path(self) -> str:
        if self.user:
            return str(_BASE_DIR / f"{self.user}.db")
        # Legacy single-account path (kept for backward compat)
        db_path = self.get("db_path")
        if not db_path:
            db_path = str(_BASE_DIR / "mailscrub.db")
            self.set("db_path", db_path)
        return db_path
