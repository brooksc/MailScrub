"""Application layer tests."""

from datetime import datetime
from unittest.mock import MagicMock

from src.application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics


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
    status_service.mark_domain_seen.assert_called_once_with("example.com")
    result = use_case.execute_on_message(msg)
    assert result is True


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
    result = use_case.execute_on_message(msg)

    assert result is False
    assert "Failed to unsubscribe" in presenter.present_error.call_args[0][0]


def test_unsubscribe_use_case_no_link_returns_false(
    message_service, status_service, presenter
):
    msg = make_message(0, unsubscribe_link=None)
    unsubscribe_service = MagicMock()
    use_case = UnsubscribeUseCase(
        message_service, status_service, unsubscribe_service, presenter
    )
    result = use_case.execute_on_message(msg)
    assert result is False
    unsubscribe_service.process_unsubscribe.assert_not_called()


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


def test_trash_messages_only_removes_succeeded_from_store(
    message_service, status_service, presenter
):
    """Only successfully trashed IDs should be removed from the local store."""
    message_service.trash_message.side_effect = [True, False, True]
    store = MagicMock()
    use_case = UnsubscribeUseCase(
        message_service, status_service, MagicMock(), presenter, message_store=store
    )

    use_case.trash_messages(["msg1", "msg2", "msg3"])

    deleted = store.delete_messages.call_args[0][0]
    assert set(deleted) == {"msg1", "msg3"}
    excluded = store.add_excluded_ids.call_args[0][0]
    assert set(excluded) == {"msg1", "msg3"}


def test_trash_messages_does_not_touch_store_when_all_fail(
    message_service, status_service, presenter
):
    message_service.trash_message.return_value = False
    store = MagicMock()
    use_case = UnsubscribeUseCase(
        message_service, status_service, MagicMock(), presenter, message_store=store
    )

    use_case.trash_messages(["msg1", "msg2"])

    store.delete_messages.assert_not_called()
    store.add_excluded_ids.assert_not_called()


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


# ---------------------------------------------------------------------------
# ListMessagesUseCase.execute_raw — reappeared detection
# ---------------------------------------------------------------------------

def _make_group(domain: str, email: str, received_ts: float) -> GroupStatistics:
    sender = EmailSender(display_name="T", email=email, domain=domain)
    msg = EmailMessage(
        id="m1", sender=sender, subject="S",
        received_at=datetime.fromtimestamp(received_ts),
        is_unread=False,
    )
    stats = MessageStatistics(total_count=1, unread_count=0, domain_total=1, domain_unread_count=0)
    return GroupStatistics(domain=domain, messages=[msg], statistics=stats)


def _make_use_case(domain_service, status_service, presenter, store=None):
    return ListMessagesUseCase(
        MagicMock(), domain_service, status_service, presenter, message_store=store
    )


def test_execute_raw_genuine_reappearance(domain_service, status_service, presenter):
    """Message received AFTER unsubscribe → in reappeared list."""
    unsub_ts = 1000.0
    group = _make_group("example.com", "t@example.com", received_ts=unsub_ts + 100)
    domain_service.group_messages.return_value = [group]
    status_service.get_unsubscribe_history.return_value = {
        "example.com": {"sender_email": "t@example.com", "attempted_at": unsub_ts, "unsubscribe_url": ""}
    }
    store = MagicMock()
    store.get_all_messages.return_value = [group.messages[0]]
    store.get_dismissed_reappeared.return_value = {}

    uc = _make_use_case(domain_service, status_service, presenter, store=store)
    groups, _, reappeared = uc.execute_raw()

    assert len(reappeared) == 1
    assert reappeared[0][0].domain == "example.com"
    assert group not in groups


def test_execute_raw_crash_leftover_surfaced_not_flagged(domain_service, status_service, presenter):
    """Message received BEFORE unsubscribe (crash leftover) → in groups, NOT reappeared."""
    unsub_ts = 2000.0
    group = _make_group("example.com", "t@example.com", received_ts=unsub_ts - 100)
    domain_service.group_messages.return_value = [group]
    status_service.get_unsubscribe_history.return_value = {
        "example.com": {"sender_email": "t@example.com", "attempted_at": unsub_ts, "unsubscribe_url": ""}
    }
    store = MagicMock()
    store.get_all_messages.return_value = [group.messages[0]]
    store.get_dismissed_reappeared.return_value = {}

    uc = _make_use_case(domain_service, status_service, presenter, store=store)
    groups, _, reappeared = uc.execute_raw()

    assert reappeared == []
    assert any(g.domain == "example.com" for g in groups)


def test_execute_raw_dismissed_suppression(domain_service, status_service, presenter):
    """Reappeared sender suppressed when dismissed count >= current new-message count."""
    unsub_ts = 1000.0
    group = _make_group("example.com", "t@example.com", received_ts=unsub_ts + 100)
    domain_service.group_messages.return_value = [group]
    status_service.get_unsubscribe_history.return_value = {
        "example.com": {"sender_email": "t@example.com", "attempted_at": unsub_ts, "unsubscribe_url": ""}
    }
    store = MagicMock()
    store.get_all_messages.return_value = [group.messages[0]]
    # Previously dismissed with count=1, same as current new_count → suppress
    store.get_dismissed_reappeared.return_value = {"t@example.com": 1}

    uc = _make_use_case(domain_service, status_service, presenter, store=store)
    _, _, reappeared = uc.execute_raw()

    assert reappeared == []


def test_execute_raw_history_match_via_sender_email(domain_service, status_service, presenter):
    """History keyed by sender email (shared-platform groups) is matched correctly."""
    unsub_ts = 1000.0
    group = _make_group("substack.com", "news@substack.com", received_ts=unsub_ts + 50)
    domain_service.group_messages.return_value = [group]
    # History keyed by sender email, not domain
    status_service.get_unsubscribe_history.return_value = {
        "news@substack.com": {"sender_email": "news@substack.com", "attempted_at": unsub_ts, "unsubscribe_url": ""}
    }
    store = MagicMock()
    store.get_all_messages.return_value = [group.messages[0]]
    store.get_dismissed_reappeared.return_value = {}

    uc = _make_use_case(domain_service, status_service, presenter, store=store)
    _, _, reappeared = uc.execute_raw()

    assert len(reappeared) == 1
