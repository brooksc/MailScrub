"""Message service implementation.

Implements Requirements:
- CORE-1: Gmail API Integration - Message operations
- MSG-1: Advanced Header Processing - Message handling
- MSG-2: Sender Normalization - Sender handling
"""


from ..interfaces import IMessageRepository
from ..models.message import EmailMessage


class MessageService:
    """Service for message operations.

    Implements:
    - CORE-1: Message handling
    """

    def __init__(self, repository: IMessageRepository):
        self.repository = repository

    def get_messages(self, query: str | None = None) -> list[EmailMessage]:
        """Get messages matching query.

        Implements:
        - CORE-1: Message retrieval
        """
        return self.repository.get_messages(query)

    def get_message_by_id(self, message_id: str) -> EmailMessage | None:
        """Get specific message by ID.

        Implements:
        - CORE-1: Message lookup
        """
        return self.repository.get_message_by_id(message_id)

    def trash_message(self, message_id: str) -> bool:
        """Move message to Trash."""
        return self.repository.trash_message(message_id)

    def update_labels(
        self, message_id: str, add_labels: list[str], remove_labels: list[str]
    ) -> bool:
        """Update message labels.

        Implements:
        - CORE-1: Label management
        """
        return self.repository.update_labels(
            message_id, add_labels, remove_labels
        )
