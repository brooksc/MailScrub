"""Console UI implementation.

Implements Requirements:
- UI-1: Message Display Format - Console UI
- UI-2: Display Table Structure - Table display
- UI-3: User Interaction - Command handling
"""

import logging

from rich.console import Console
from rich.prompt import Confirm, Prompt

from ..application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from ..infrastructure.gmail import GmailRepository
from ..presentation.presenters import ConsolePresenter

logger = logging.getLogger(__name__)
console = Console()


PAGE_SIZE = 15


class ConsoleUI:
    """Console UI implementation with enhanced user interaction."""

    def __init__(
        self,
        list_messages_use_case: ListMessagesUseCase,
        unsubscribe_use_case: UnsubscribeUseCase,
        presenter: ConsolePresenter
    ):
        """Initialize UI."""
        self.list_messages = list_messages_use_case
        self.unsubscribe = unsubscribe_use_case
        self.presenter = presenter
        pass

    @staticmethod
    def _sender_label(group) -> str:
        if not group.messages:
            return group.domain
        m = group.messages[0]
        return m.sender.display_name or m.sender.email

    def _handle_unsubscribe(self, group) -> bool:
        """Unsubscribe from a sender group. Returns True if action was taken."""
        sender = self._sender_label(group)
        if not Confirm.ask(f"Unsubscribe from [cyan]{sender}[/cyan]?", default=True):
            return False
        unsub_msg = next((m for m in group.messages if m.has_unsubscribe), None)
        if not unsub_msg:
            self.presenter.present_error("No unsubscribe link found.")
            return False
        try:
            self.unsubscribe.execute_on_message(unsub_msg)
        except Exception as e:
            self.presenter.present_error(f"Failed to unsubscribe: {e}")
        return True

    def _handle_ignore(self, group) -> bool:
        """Label all messages in the group as ignored. Returns True if action was taken."""
        sender = self._sender_label(group)
        if not Confirm.ask(f"Ignore [cyan]{sender}[/cyan]?", default=True):
            return False
        for msg in group.messages:
            try:
                self.unsubscribe.execute_ignore(msg.id)
            except Exception as e:
                logger.warning(f"Failed to label {msg.id} as ignored: {e}")
        self.presenter.present_success(f"Ignored {sender}")
        return True

    def run(self, list_mode: bool = False, show_all: bool = False, new: bool = False, user: str | None = None, testing: bool = False) -> None:
        """Run the UI.

        Args:
            list_mode (bool): If True, only list messages and exit
            show_all (bool): If True, show all messages including previously seen ones
            new (bool): If True, add new Gmail account
            user (str): Specify Gmail account to use
            testing (bool): If True, enable testing mode
        """
        try:
            logger.debug("Starting UI run method")
            logger.debug(f"Parameters: list_mode={list_mode}, show_all={show_all}, new={new}, user={user}, testing={testing}")

            if new:
                logger.debug("Initializing new account")
                # Initialize new account first
                repo = self.list_messages.message_service.repository
                assert isinstance(repo, GmailRepository)
                repo.initialize_new_account()
                self.presenter.present_success("Successfully initialized new Gmail account")
                logger.debug("New account initialization completed")
                return

            try:
                logger.debug("Attempting to initialize Gmail service")
                # Initialize service if needed
                repo = self.list_messages.message_service.repository
                assert isinstance(repo, GmailRepository)
                repo._initialize_service()
                logger.debug("Gmail service initialization successful")
            except Exception as e:
                logger.debug(f"Gmail service initialization failed: {str(e)}")
                if "No valid credentials found" in str(e):
                    self.presenter.present_error(
                        "No valid Gmail credentials found. Please run with --new flag to set up a new account."
                    )
                    return
                raise  # Re-raise other exceptions

            logger.debug("Fetching messages from Gmail API")
            # Get all groups, then paginate display
            all_groups, seen_domains, _reappeared = self.list_messages.execute_raw(show_all=show_all)
            logger.debug(f"Retrieved {len(all_groups)} message groups")

            if list_mode:
                self.presenter.present_messages(all_groups, seen_domains)
                return

            page = 0
            total_pages = max(1, (len(all_groups) + PAGE_SIZE - 1) // PAGE_SIZE)

            def show_page():
                start = page * PAGE_SIZE
                self.presenter.present_messages(all_groups[start:start + PAGE_SIZE], seen_domains)
                if total_pages > 1:
                    console.print(f"Page {page + 1}/{total_pages} — [cyan]n[/cyan]=next  [cyan]p[/cyan]=prev")

            show_page()

            logger.debug("Entering command processing loop")
            while True:
                try:
                    command = Prompt.ask("Command (? for help, q to quit)")
                    logger.debug(f"Received command: {command}")

                    if command == "q":
                        logger.debug("Quit command received")
                        break

                    if command == "n":
                        page = min(page + 1, total_pages - 1)
                        show_page()
                        continue

                    if command == "p":
                        page = max(page - 1, 0)
                        show_page()
                        continue

                    if command == "l":
                        show_page()
                        continue

                    if command == "?":
                        console.print(
                            "  [cyan]<#>u[/cyan] or [cyan]u<#>[/cyan] unsubscribe  "
                            "[cyan]<#>i[/cyan] or [cyan]i<#>[/cyan] ignore  "
                            "[cyan]n[/cyan]/[cyan]p[/cyan] next/prev  "
                            "[cyan]l[/cyan] list  [cyan]q[/cyan] quit\n"
                            "  Example: [cyan]3u[/cyan] or [cyan]u3[/cyan] — unsubscribe from row 3"
                        )
                        continue

                    # Parse number+action in either order: "3u", "u3", "12i", "i12"
                    import re as _re
                    m = _re.fullmatch(r"([ui])(\d+)|(\d+)([ui])", command)
                    if m:
                        action = (m.group(1) or m.group(4))
                        row_num = int(m.group(2) or m.group(3))
                        start = page * PAGE_SIZE
                        page_groups = all_groups[start:start + PAGE_SIZE]
                        if row_num < 1 or row_num > len(page_groups):
                            self.presenter.present_error(f"Row must be 1–{len(page_groups)}.")
                        else:
                            group = page_groups[row_num - 1]
                            taken = (
                                self._handle_unsubscribe(group)
                                if action == "u"
                                else self._handle_ignore(group)
                            )
                            if taken and group in all_groups:
                                all_groups.remove(group)
                                total_pages = max(1, (len(all_groups) + PAGE_SIZE - 1) // PAGE_SIZE)
                                page = min(page, total_pages - 1)
                                show_page()
                        continue

                    logger.debug(f"Invalid command received: {command}")
                    self.presenter.present_error("Invalid command. Type ? for help.")

                except KeyboardInterrupt:
                    logger.debug("KeyboardInterrupt received")
                    if Confirm.ask("\nAre you sure you want to quit?"):
                        break

        except Exception as e:
            logger.error(f"Error in UI: {str(e)}", exc_info=True)
            self.presenter.present_error(str(e))
