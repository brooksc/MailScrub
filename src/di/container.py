"""Dependency injection container."""

import logging

from rich.console import Console

from ..application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from ..domain.services import DomainService, StatusService, UnsubscribeService
from ..domain.services.message import MessageService
from ..infrastructure.config import ConfigManager
from ..infrastructure.database import Database, MessageCache, StatusRepository
from ..infrastructure.gmail import GmailRepository
from ..infrastructure.message_store import GmailSyncer, MessageStore
from ..infrastructure.unsubscribe import UnsubscribeClient
from ..presentation.presenters import ConsolePresenter
from ..ui.console import ConsoleUI
from ..ui.tui import MailScrubApp


class Container:
    def __init__(self, config_path: str | None = None, user: str | None = None):
        self.logger = logging.getLogger(__name__)
        try:
            self.config = ConfigManager(config_path, user=user)
            self.console = Console()
            self.presenter = ConsolePresenter(self.console)
        except Exception:
            self.logger.exception("Container initialization failed")
            raise

    def init_infrastructure(self) -> None:
        try:
            self._db = Database(self.config.get_db_path())
            self.message_cache = MessageCache(self._db)
            self.message_cache.purge_expired()
            self.message_store = MessageStore(self._db)
            self.gmail_repo = GmailRepository(self.config, cache=self.message_cache)
            self.gmail_syncer = GmailSyncer(self.gmail_repo, self.message_store)
            self.status_repo = StatusRepository(self.config, db=self._db)
            self.unsubscribe_client = UnsubscribeClient(gmail_repo=self.gmail_repo)
        except Exception:
            self.logger.exception("Infrastructure initialization failed")
            raise

    def init_services(self) -> None:
        try:
            self.domain_service = DomainService()
            self.message_service = MessageService(repository=self.gmail_repo)
            self.status_service = StatusService(self.status_repo)
            self.unsubscribe_service = UnsubscribeService(self.unsubscribe_client)

            self.list_messages = ListMessagesUseCase(
                self.message_service,
                self.domain_service,
                self.status_service,
                self.presenter,
                message_store=self.message_store,
            )
            self.unsubscribe = UnsubscribeUseCase(
                self.message_service,
                self.status_service,
                self.unsubscribe_service,
                self.presenter,
                message_store=self.message_store,
            )

            self.ui = ConsoleUI(self.list_messages, self.unsubscribe, self.presenter)
            self.tui = MailScrubApp(
                self.list_messages,
                self.unsubscribe,
                gmail_syncer=self.gmail_syncer,
                message_store=self.message_store,
                gmail_repo=self.gmail_repo,
            )
        except Exception:
            self.logger.exception("Service initialization failed")
            raise
