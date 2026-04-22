"""Tests for console UI."""

from unittest.mock import MagicMock, patch

import pytest

from src.application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from src.infrastructure.gmail import GmailRepository
from src.presentation.presenters import ConsolePresenter
from src.ui.console import ConsoleUI


@pytest.fixture
def mock_list_messages():
    mock = MagicMock(spec=ListMessagesUseCase)
    mock.execute.return_value = []
    mock.execute_raw.return_value = ([], set())
    return mock


@pytest.fixture
def mock_unsubscribe():
    mock = MagicMock(spec=UnsubscribeUseCase)
    mock.execute = MagicMock()
    return mock


@pytest.fixture
def mock_presenter():
    return MagicMock(spec=ConsolePresenter)


@pytest.fixture
def console_ui(mock_list_messages, mock_unsubscribe, mock_presenter):
    return ConsoleUI(mock_list_messages, mock_unsubscribe, mock_presenter)


def test_console_ui_constructs(console_ui):
    assert console_ui is not None


def test_run_list_mode_calls_execute(console_ui, mock_list_messages):
    with patch("src.ui.console.ConsoleUI.run", wraps=console_ui.run):
        mock_list_messages.message_service = MagicMock()
        mock_list_messages.message_service.repository = MagicMock(spec=GmailRepository)
        console_ui.run(list_mode=True)
    mock_list_messages.execute_raw.assert_called_once()
