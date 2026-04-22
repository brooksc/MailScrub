"""Domain models package.

Implements Requirements:
- MSG-1: Message Structure - Core models
- MSG-2: Message Status - Status tracking
"""

from .message import EmailMessage
from .sender import EmailSender
from .statistics import GroupStatistics, MessageStatistics

__all__ = [
    'EmailMessage',
    'EmailSender',
    'GroupStatistics',
    'MessageStatistics',
]
