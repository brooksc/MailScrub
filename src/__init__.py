"""MailScrub package."""

from .application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from .domain.exceptions import DomainError, MessageError
from .domain.models import EmailMessage, EmailSender, GroupStatistics, MessageStatistics
from .domain.services import DomainService, MessageService, StatusService, UnsubscribeService
from .infrastructure.config import ConfigManager
from .infrastructure.database import Database, MessageCache
from .infrastructure.gmail import GmailRepository
from .infrastructure.unsubscribe import UnsubscribeClient

__all__ = [
    "EmailMessage",
    "EmailSender",
    "MessageStatistics",
    "GroupStatistics",
    "MessageService",
    "DomainService",
    "StatusService",
    "UnsubscribeService",
    "DomainError",
    "MessageError",
    "ListMessagesUseCase",
    "UnsubscribeUseCase",
    "GmailRepository",
    "Database",
    "MessageCache",
    "UnsubscribeClient",
    "ConfigManager",
]
