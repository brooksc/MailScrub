"""Application layer tests."""

from datetime import datetime
from unittest.mock import MagicMock

from src.application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender


def make_message(idx: int = 0, is_unread: bool = False, unsubscribe_link=None) -> EmailMessage:
    sender = EmailSender(display_name="Test", email="t@example.com", domain="example.com")
    return EmailMessage(
        id=f"msg{idx}",
        sender=sender,
        subject=f"Subject {idx}",
        received_at=datetime(2024, 1, 1),
        is_unread=is_unread,
        unsubscribe_link=unsubscribe_link,
    )


def test_list_messages_use_case(
    message_service, domain_service, status_service, presenter
):
    sample = [make_message(i) for i in range(3)]
    message_service.get_messages.return_value = sample
    status_service.get_seen_domains.return_value = set()
    domain_service.group_messages.return_value = []

    use_case = ListMessagesUseCase(
        message_service, domain_service, status_service, presenter
    )
    use_case.execute()

    message_service.get_messages.assert_called_once()
    domain_service.group_messages.assert_called_once_with(sample)
    presenter.present_messages.assert_called_once()


def test_list_messages_passes_seen_domains(
    message_service, domain_service, status_service, presenter
):
    seen = {"example.com"}
    status_service.get_seen_domains.return_value = seen
    domain_service.group_messages.return_value = []
    message_service.get_messages.return_value = []

    use_case = ListMessagesUseCase(
        message_service, domain_service, status_service, presenter
    )
    use_case.execute()

    args = presenter.present_messages.call_args[0]
    assert seen in args


def test_unsubscribe_use_case_no_message(
    message_service, status_service, presenter
):
    message_service.get_message_by_id.return_value = None
    unsubscribe_service = MagicMock()

    use_case = UnsubscribeUseCase(
        message_service, status_service, unsubscribe_service, presenter
    )
    use_case.execute("nonexistent")

    presenter.present_error.assert_called_once_with("Message not found")
    unsubscribe_service.process_unsubscribe.assert_not_called()


def test_unsubscribe_use_case_no_link(
    message_service, status_service, presenter
):
    msg = make_message(0, unsubscribe_link=None)
    message_service.get_message_by_id.return_value = msg
    unsubscribe_service = MagicMock()

    use_case = UnsubscribeUseCase(
        message_service, status_service, unsubscribe_service, presenter
    )
    use_case.execute("msg0")

    presenter.present_error.assert_called_once_with("No unsubscribe link found")


def test_unsubscribe_use_case_success(
    message_service, status_service, presenter
):
    msg = make_message(0, unsubscribe_link="https://example.com/unsub")
    message_service.get_message_by_id.return_value = msg
    unsubscribe_service = MagicMock()
    unsubscribe_service.process_unsubscribe.return_value = True

    use_case = UnsubscribeUseCase(
        message_service, status_service, unsubscribe_service, presenter
    )
    use_case.execute("msg0")

    unsubscribe_service.process_unsubscribe.assert_called_once_with(msg, from_email=None)
    presenter.present_success.assert_called_once()
    status_service.mark_domain_seen.assert_called_once_with("example.com")


def test_unsubscribe_use_case_failure(
    message_service, status_service, presenter
):
    msg = make_message(0, unsubscribe_link="https://example.com/unsub")
    message_service.get_message_by_id.return_value = msg
    unsubscribe_service = MagicMock()
    unsubscribe_service.process_unsubscribe.return_value = False

    use_case = UnsubscribeUseCase(
        message_service, status_service, unsubscribe_service, presenter
    )
    use_case.execute("msg0")

    assert "Failed to unsubscribe" in presenter.present_error.call_args[0][0]


# ---------------------------------------------------------------------------
# trash_messages
# ---------------------------------------------------------------------------

def test_trash_messages_trashes_each_id(message_service, status_service, presenter):
    message_service.trash_message.return_value = True
    use_case = UnsubscribeUseCase(message_service, status_service, MagicMock(), presenter)

    count = use_case.trash_messages(["msg1", "msg2", "msg3"])

    assert count == 3
    assert message_service.trash_message.call_count == 3
    message_service.trash_message.assert_any_call("msg1")
    message_service.trash_message.assert_any_call("msg2")
    message_service.trash_message.assert_any_call("msg3")


def test_trash_messages_returns_correct_count_on_partial_failure(
    message_service, status_service, presenter
):
    # msg1 succeeds, msg2 fails, msg3 succeeds
    message_service.trash_message.side_effect = [True, False, True]
    use_case = UnsubscribeUseCase(message_service, status_service, MagicMock(), presenter)

    count = use_case.trash_messages(["msg1", "msg2", "msg3"])
    assert count == 2


def test_trash_messages_empty_list(message_service, status_service, presenter):
    use_case = UnsubscribeUseCase(message_service, status_service, MagicMock(), presenter)
    count = use_case.trash_messages([])
    assert count == 0
    message_service.trash_message.assert_not_called()


def test_trash_messages_single_message(message_service, status_service, presenter):
    message_service.trash_message.return_value = True
    use_case = UnsubscribeUseCase(message_service, status_service, MagicMock(), presenter)
    count = use_case.trash_messages(["only-one"])
    assert count == 1
