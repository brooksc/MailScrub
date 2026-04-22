"""Infrastructure layer package.

Implements Requirements:
- CORE-1: Gmail API Integration - Infrastructure organization
"""

from .config import ConfigManager
from .database import Database, MessageCache
from .gmail import GmailRepository
from .unsubscribe import UnsubscribeClient

__all__ = [
    'GmailRepository',
    'MessageCache',
    'UnsubscribeClient',
    'Database',
    'ConfigManager'
]
