"""Domain services package.

Implements Requirements:
- CORE-1: Gmail API Integration - Service organization
"""

from .domain import DomainService
from .message import MessageService
from .status import StatusService
from .unsubscribe import UnsubscribeService

__all__ = [
    'MessageService',
    'DomainService',
    'StatusService',
    'UnsubscribeService'
]
