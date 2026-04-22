"""Domain layer package.

Implements Requirements:
- MSG-1: Message Structure - Domain models
- MSG-2: Message Status - Status tracking
"""

from .exceptions import (
    DomainError,
    MessageError,
)
from .interfaces import (
    IMessageRepository,
    IStatusRepository,
)
from .models import (
    EmailMessage,
    EmailSender,
    GroupStatistics,
    MessageStatistics,
)
from .services import (
    DomainService,
    MessageService,
    StatusService,
    UnsubscribeService,
)

__all__ = [
    # Models
    'EmailMessage',
    'EmailSender',
    'GroupStatistics',
    'MessageStatistics',

    # Services
    'MessageService',
    'DomainService',
    'StatusService',
    'UnsubscribeService',

    # Interfaces
    'IMessageRepository',
    'IStatusRepository',

    # Exceptions
    'DomainError',
    'MessageError',
]
