"""Presentation interfaces.

Implements Requirements:
- UI-1: Message Display Format - Interface definitions
- UI-2: Display Table Structure - Interface contracts
"""

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager

from ..domain.models.statistics import GroupStatistics


class IPresenter(ABC):
    """Interface for presenters.

    Implements:
    - UI-1: Display format
    """

    @abstractmethod
    def present_messages(self, groups: list[GroupStatistics], seen_domains: set[str]) -> None:
        """Present message groups."""
        pass

    @abstractmethod
    def present_error(self, error: str) -> None:
        """Present error message."""
        pass

    @abstractmethod
    def present_success(self, message: str) -> None:
        """Present success message."""
        pass

    @abstractmethod
    def loading(self, message: str) -> AbstractContextManager:
        """Return a context manager that shows a spinner while work is in progress."""
        pass
