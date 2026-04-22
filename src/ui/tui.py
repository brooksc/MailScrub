"""Full-screen TUI for MailScrub using Textual."""

from __future__ import annotations

import logging
import urllib.parse
import webbrowser
from datetime import UTC, datetime

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Static
from textual.worker import Worker, WorkerState

from ..application.use_cases import ListMessagesUseCase, UnsubscribeUseCase
from ..domain.models.statistics import GroupStatistics
from ..presentation.view_models import MessageTableViewModel

logger = logging.getLogger(__name__)

_SORT_CYCLE = ["count", "sender", "age"]
_SORT_LABELS = {"count": "count ↓", "sender": "sender A–Z", "age": "newest first"}


class ProgressScreen(ModalScreen[None]):
    """Blocking progress modal. Pushed before a long operation, dismissed when done."""

    DEFAULT_CSS = """
    ProgressScreen > Static {
        border: round cyan;
        width: 60;
        height: auto;
        content-align: center middle;
        margin: 4 0 0 0;
        padding: 1 2;
    }
    """

    def __init__(self, initial: str) -> None:
        super().__init__()
        self._initial = initial

    def compose(self) -> ComposeResult:
        yield Static(self._initial, id="progress-status")

    def update(self, message: str) -> None:
        self.query_one("#progress-status", Static).update(message)


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no confirmation modal."""

    BINDINGS = [
        Binding("y", "yes", "Yes"),
        Binding("enter", "yes", "Yes"),
        Binding("n", "no", "No"),
        Binding("escape", "no", "No"),
    ]


    DEFAULT_CSS = """
    ConfirmScreen > Static {
        border: round cyan;
        width: 70;
        height: auto;
        max-height: 24;
        content-align: center middle;
        margin: 4 0 0 0;
    }
    """

    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        yield Static(
            f"\n  {self._message}\n\n  [bold cyan]Y[/bold cyan]es  /  [dim]n[/dim]o  [dim](Enter = Yes)[/dim]"
        )

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class HelpScreen(ModalScreen[None]):
    """Full-screen help overlay."""

    BINDINGS = [Binding("escape", "dismiss_screen", "Close")]

    DEFAULT_CSS = """
    HelpScreen > Static {
        border: round cyan;
        width: 56;
        height: 40;
        margin: 2 0 0 14;
    }
    """

    def compose(self) -> ComposeResult:
        yield Static(
            "\n"
            "  [bold cyan]MailScrub[/bold cyan]\n"
            "  Finds subscription emails in Gmail, groups\n"
            "  them by sender, and lets you unsubscribe,\n"
            "  ignore, or delete in bulk.\n"
            "\n"
            "  [bold cyan]Navigation[/bold cyan]\n"
            "  ↑ / k      Move up\n"
            "  ↓ / j      Move down\n"
            "  PgUp       Page up\n"
            "  PgDn       Page down\n"
            "  g / Home   Jump to top\n"
            "  G / End    Jump to bottom\n"
            "\n"
            "  [bold cyan]Cursor (no selection needed)[/bold cyan]\n"
            "  v          Open message in browser\n"
            "  s          Search sender in Gmail\n"
            "\n"
            "  [bold cyan]Select first, then act[/bold cyan]\n"
            "  Space      Toggle row · moves cursor down\n"
            "  a          Select all / deselect all\n"
            "  *          Select visible rows\n"
            "\n"
            "  [bold cyan]Require selection (appear when ready)[/bold cyan]\n"
            "  u          Unsubscribe from selected senders\n"
            "  i          Ignore selected senders\n"
            "  d          Delete emails from selected senders\n"
            "\n"
            "  [bold cyan]Other[/bold cyan]\n"
            "  o          Cycle sort: count → sender → age\n"
            "  r          Refresh / sync\n"
            "  e          View ignored senders\n"
            "  ?          This help\n"
            "  q          Quit\n"
        )

    def action_dismiss_screen(self) -> None:
        self.dismiss()


class ReappearedScreen(ModalScreen[set]):
    """Shown on load when senders have reappeared after a previous unsubscribe attempt.

    Dismisses with a set[str] of sender emails the user took action on (vs skipped).
    Only skipped senders get their counts saved — acted-on senders are cleared so they
    reappear if messages remain after a crash/partial delete.
    """

    BINDINGS = [
        Binding("v", "view_email", "View"),
        Binding("o", "open_browser", "Open"),
        Binding("d", "delete_emails", "Delete"),
        Binding("b", "both", "Both"),
        Binding("f", "forget", "Forget"),
        Binding("escape,q", "dismiss_screen", "Skip all"),
    ]

    DEFAULT_CSS = """
    ReappearedScreen > Static {
        border: round yellow;
        width: 80;
        height: auto;
        max-height: 14;
        margin: 2 0 0 5;
        padding: 1 2;
    }
    """

    def __init__(
        self,
        reappeared: list[tuple[GroupStatistics, dict]],
        unsubscribe_use_case: UnsubscribeUseCase,
    ) -> None:
        super().__init__()
        self._reappeared = reappeared
        self._unsubscribe = unsubscribe_use_case
        self._idx = 0
        self._acted: set[str] = set()  # sender emails where user took an action (not skipped)

    def compose(self) -> ComposeResult:
        yield Static(self._render_current())

    def _render_current(self) -> str:
        group, hist = self._reappeared[self._idx]
        total = len(self._reappeared)
        sender = (group.messages[0].sender.display_name or group.messages[0].sender.email or group.domain) if group.messages else group.domain
        attempted = datetime.fromtimestamp(hist["attempted_at"], tz=UTC).strftime("%Y-%m-%d")
        count = len(group.messages)
        url = hist.get("unsubscribe_url") or ""
        lines = [
            f"[bold yellow]⚠  Unsubscribe ignored[/bold yellow]  [dim]{self._idx + 1}/{total}[/dim]\n",
            f"[bold]{sender}[/bold] kept emailing after you unsubscribed\n",
            f"  [dim]unsubscribed {attempted} · {count} new email{'s' if count != 1 else ''}[/dim]",
        ]
        if url:
            lines.append(f"  [dim]{url[:68]}{'…' if len(url) > 68 else ''}[/dim]")
        lines.append(
            "\n[bold]v[/bold] View email  "
            "[bold]o[/bold] Open browser  "
            "[bold]d[/bold] Delete emails  "
            "[bold]b[/bold] Both  "
            "[bold]f[/bold] Forget  "
            "[bold]Esc[/bold] Skip all"
        )
        return "\n".join(lines)

    def _sender_key(self) -> str:
        group, _ = self._reappeared[self._idx]
        return group.messages[0].sender.email if group.messages else group.domain

    def _advance(self) -> None:
        self._idx += 1
        if self._idx >= len(self._reappeared):
            self.dismiss(self._acted)
        else:
            self.query_one(Static).update(self._render_current())

    def action_view_email(self) -> None:
        group, _ = self._reappeared[self._idx]
        if group.messages:
            webbrowser.open(f"https://mail.google.com/mail/u/0/#all/{group.messages[0].id}")

    def action_open_browser(self) -> None:
        _, hist = self._reappeared[self._idx]
        url = hist.get("unsubscribe_url")
        if url:
            webbrowser.open(url)
        self._acted.add(self._sender_key())
        self._advance()

    def action_delete_emails(self) -> None:
        group, _ = self._reappeared[self._idx]
        ids = [m.id for m in group.messages]
        self.run_worker(lambda _ids=ids: self._unsubscribe.trash_messages(_ids), thread=True)
        self._acted.add(self._sender_key())
        self._advance()

    def action_both(self) -> None:
        group, hist = self._reappeared[self._idx]
        url = hist.get("unsubscribe_url")
        if url:
            webbrowser.open(url)
        ids = [m.id for m in group.messages]
        self.run_worker(lambda _ids=ids: self._unsubscribe.trash_messages(_ids), thread=True)
        self._acted.add(self._sender_key())
        self._advance()

    def action_forget(self) -> None:
        group, _ = self._reappeared[self._idx]
        if group.messages:
            self._unsubscribe.clear_reappeared([group.messages[0].sender.email])
        self._acted.add(self._sender_key())
        self._advance()

    def action_dismiss_screen(self) -> None:
        self.dismiss(self._acted)


class IgnoredScreen(ModalScreen[None]):
    """Full-screen list of ignored senders with option to restore."""

    BINDINGS = [
        Binding("escape", "dismiss_screen", "Close"),
        Binding("space", "toggle_select", "Select"),
        Binding("a", "select_all", "All"),
        Binding("r", "restore", "Restore", show=False),
    ]

    DEFAULT_CSS = """
    IgnoredScreen DataTable { height: 1fr; }
    IgnoredScreen #ig-status {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }
    """

    def __init__(self, message_store) -> None:
        super().__init__()
        self._store = message_store
        self._senders: list[dict] = []
        self._selected: set[str] = set()

    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("", id="ig-status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("", key="sel", width=3)
        table.add_column("Sender Email", key="sender", width=38)
        table.add_column("Domain", key="domain", width=24)
        table.add_column("Msgs", key="count", width=6)
        table.add_column("Ignored On", key="ignored_at", width=12)
        self._load()

    def _load(self) -> None:
        self._senders = self._store.get_ignored_senders()
        self._selected.clear()
        self._rebuild()

    def _rebuild(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        status = self.query_one("#ig-status", Static)
        if not self._senders:
            status.update("No ignored senders — all senders are visible in the main view.")
            return
        for s in self._senders:
            sel = Text("[x]", style="cyan") if s["group_key"] in self._selected else Text("[ ]")
            age = datetime.fromtimestamp(s["ignored_at"]).strftime("%Y-%m-%d")
            table.add_row(sel, s["group_key"], s["domain"] or "—", str(s["count"]), age, key=s["group_key"])
        n_sel = len(self._selected)
        status.update(
            f"{len(self._senders)} ignored sender(s)"
            + (f" · {n_sel} selected — press [bold]r[/bold] to restore" if n_sel else "")
        )
        self.refresh_bindings()

    def _cursor_sender(self) -> str | None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        try:
            key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            return str(key.value)
        except Exception:
            return None

    def action_toggle_select(self) -> None:
        sender = self._cursor_sender()
        if sender is None:
            return
        if sender in self._selected:
            self._selected.discard(sender)
        else:
            self._selected.add(sender)
        marker = Text("[x]", style="cyan") if sender in self._selected else Text("[ ]")
        table = self.query_one(DataTable)
        table.update_cell(sender, "sel", marker)
        table.move_cursor(row=min(table.cursor_row + 1, table.row_count - 1))
        self._update_status()
        self.refresh_bindings()

    def _update_status(self) -> None:
        n_sel = len(self._selected)
        self.query_one("#ig-status", Static).update(
            f"{len(self._senders)} ignored sender(s)"
            + (f" · {n_sel} selected — press [bold]r[/bold] to restore" if n_sel else "")
        )

    def action_select_all(self) -> None:
        if len(self._selected) == len(self._senders):
            self._selected.clear()
        else:
            self._selected = {s["group_key"] for s in self._senders}
        self._rebuild()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "restore":
            return bool(self._selected)
        return True

    def action_restore(self) -> None:
        for group_key in list(self._selected):
            self._store.remove_ignored_sender(group_key)
        self._load()

    def action_dismiss_screen(self) -> None:
        self.dismiss()


class MailScrubApp(App[None]):
    """Full-screen TUI for MailScrub."""

    TITLE = "MailScrub"

    CSS = """
    DataTable { height: 1fr; }
    #status {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "jump_top", "Top", show=False),
        Binding("G", "jump_bottom", "Bottom", show=False),
        Binding("space", "toggle_select", "Select"),
        Binding("a", "select_all", "All"),
        Binding("asterisk", "select_visible", "Visible"),
        Binding("v", "view_in_browser", "View"),
        Binding("s", "search_in_gmail", "Search"),
        Binding("d", "delete", "Delete", show=False),
        Binding("u", "unsubscribe", "Unsubscribe", show=False),
        Binding("i", "ignore", "Ignore", show=False),
        Binding("o", "cycle_sort", "Sort"),
        Binding("r", "refresh", "Refresh"),
        Binding("e", "ignored_screen", "Ignored"),
        Binding("question_mark", "help_screen", "Help"),
    ]

    def __init__(
        self,
        list_messages_use_case: ListMessagesUseCase,
        unsubscribe_use_case: UnsubscribeUseCase,
        show_all: bool = False,
        gmail_syncer=None,
        message_store=None,
        gmail_repo=None,
    ) -> None:
        super().__init__()
        self._list_messages = list_messages_use_case
        self._unsubscribe = unsubscribe_use_case
        self._show_all = show_all
        self._gmail_syncer = gmail_syncer
        self._message_store = message_store
        self._gmail_repo = gmail_repo
        self._groups: list[GroupStatistics] = []
        self._seen_domains: set[str] = set()
        self._selected: set[str] = set()
        self._sort_key: str = "count"
        self._read_only: bool = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("Loading…", id="status")
        yield Footer()

    def _col_widths(self) -> tuple[int, int]:
        # Fixed cols: sel(3) + age(10) + stats(14) + ~2 padding per col × 5 = 37
        flex = max(40, self.app.size.width - 37)
        sender_w = max(20, int(flex * 0.42))
        subject_w = max(20, flex - sender_w)
        return sender_w, subject_w

    def _setup_columns(self) -> None:
        table = self.query_one(DataTable)
        table.clear(columns=True)
        sender_w, subject_w = self._col_widths()
        table.add_column("", key="sel", width=3)
        table.add_column("Sender", key="sender", width=sender_w)
        table.add_column("Latest Subject", key="subject", width=subject_w)
        table.add_column("Age", key="age", width=10)
        table.add_column("Msgs (%unread)", key="stats", width=14)

    def on_mount(self) -> None:
        self._setup_columns()
        self._load_data()
        if self._message_store and not self._message_store.has_seen_help():
            self._message_store.mark_help_seen()
            self.push_screen(HelpScreen())

    def on_resize(self) -> None:
        self._setup_columns()
        self._rebuild_table()

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def _load_data(self) -> None:
        self._set_status("Fetching emails…")
        self.run_worker(self._fetch_worker, exclusive=True, thread=True, name="fetch")

    def _fetch_worker(self) -> tuple:
        return self._list_messages.execute_raw(show_all=self._show_all)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.ERROR:
            self._set_status(f"Error: {event.worker.error}", kind="error")
            return

        if event.state != WorkerState.SUCCESS:
            return

        name = event.worker.name
        result = event.worker.result

        if result is None:
            return

        if name == "fetch":
            groups, seen, reappeared = result
            self._seen_domains = seen
            self._groups = groups
            self._selected.clear()
            self._rebuild_table()
            vm = MessageTableViewModel(self._groups, self._seen_domains)
            ro_tag = " · [yellow]read-only[/yellow]" if self._read_only else ""
            self.sub_title = (
                f"{vm.total_messages} msgs · {vm.unread_messages} unread · "
                f"{len(self._groups)} senders{ro_tag}"
            )
            reappeared_multi = [(g, h) for g, h in reappeared if len(g.messages) > 0]
            if reappeared_multi:
                def _save_dismissed(acted: set, _rm=reappeared_multi) -> None:
                    if not self._message_store:
                        return
                    acted = acted or set()
                    dismissed = self._message_store.get_dismissed_reappeared()
                    for g, hist in _rm:
                        key = g.messages[0].sender.email if g.messages else g.domain
                        if key in acted:
                            dismissed.pop(key, None)  # clear — reappear if messages linger
                        else:
                            # Store count of messages received after the unsubscribe attempt
                            new_count = sum(
                                1 for m in g.messages
                                if m.received_at.timestamp() > hist["attempted_at"]
                            )
                            dismissed[key] = new_count
                    self._message_store.set_dismissed_reappeared(dismissed)
                self.push_screen(ReappearedScreen(reappeared_multi, self._unsubscribe), callback=_save_dismissed)
                self._set_status(
                    f"{len(self._groups)} senders · "
                    f"[yellow]{len(reappeared_multi)} ignored your unsubscribe[/yellow]"
                )
            else:
                self._set_status(
                    f"{len(self._groups)} sender{'s' if len(self._groups) != 1 else ''} found"
                )

        elif name == "unsubscribe":
            done, acted_domains = result
            self._groups = [g for g in self._groups if g.domain not in acted_domains]
            self._selected -= set(acted_domains)
            self._rebuild_table()
            self._set_status(f"Unsubscribed from {done} sender(s).", kind="success")

        elif name == "ignore":
            done, acted_domains = result
            self._groups = [g for g in self._groups if g.domain not in acted_domains]
            self._selected -= set(acted_domains)
            self._rebuild_table()
            self._set_status(f"Ignored {done} sender(s).", kind="success")

        elif name == "delete":
            acted_domains: set[str] = result
            self._groups = [g for g in self._groups if g.domain not in acted_domains]
            self._selected -= acted_domains
            self._rebuild_table()
            self._set_status("Deleted.", kind="success")

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action in ("delete", "unsubscribe", "ignore") and self._read_only:
            return False
        if action in ("delete", "unsubscribe", "ignore"):
            return bool(self._selected)
        if action == "ignored_screen":
            return self._message_store is not None
        return True

    def _sorted_groups(self) -> list[GroupStatistics]:
        groups = list(self._groups)
        if self._sort_key == "sender":
            groups.sort(key=lambda g: self._sender_label(g).lower())
        elif self._sort_key == "age":
            groups.sort(
                key=lambda g: max((m.received_at for m in g.messages), default=datetime.min),
                reverse=True,
            )
        else:  # count
            groups.sort(key=lambda g: len(g.messages), reverse=True)
        return groups

    def _rebuild_table(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        sorted_groups = self._sorted_groups()
        vm = MessageTableViewModel(sorted_groups, self._seen_domains)
        for group, row in zip(sorted_groups, vm.rows):
            sel = Text("[x]", style="cyan") if group.domain in self._selected else Text("[ ]")
            if row.is_unread:
                sender = f"[bold]{row.sender}[/bold]"
                subject = f"[bold]{row.subject}[/bold]"
            else:
                sender = f"[dim]{row.sender}[/dim]"
                subject = f"[dim]{row.subject}[/dim]"
            table.add_row(
                sel,
                sender,
                subject,
                row.age,
                row.stats,
                key=group.domain,
            )
        self.refresh_bindings()

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _set_status(self, message: str, kind: str = "info") -> None:
        status = self.query_one("#status", Static)
        status.update(message)
        status.set_class(kind == "error", "error")
        status.set_class(kind == "success", "success")

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def action_cursor_down(self) -> None:
        table = self.query_one(DataTable)
        row = min(table.cursor_row + 1, table.row_count - 1)
        table.move_cursor(row=row)

    def action_cursor_up(self) -> None:
        table = self.query_one(DataTable)
        row = max(table.cursor_row - 1, 0)
        table.move_cursor(row=row)

    def action_jump_top(self) -> None:
        self.query_one(DataTable).move_cursor(row=0)

    def action_jump_bottom(self) -> None:
        table = self.query_one(DataTable)
        table.move_cursor(row=max(0, table.row_count - 1))

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _cursor_domain(self) -> str | None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        try:
            key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
            return str(key.value)
        except Exception:
            return None

    def action_toggle_select(self) -> None:
        domain = self._cursor_domain()
        if domain is None:
            return
        if domain in self._selected:
            self._selected.discard(domain)
        else:
            self._selected.add(domain)
        marker = Text("[x]", style="cyan") if domain in self._selected else Text("[ ]")
        self.query_one(DataTable).update_cell(domain, "sel", marker)
        self.refresh_bindings()
        self.action_cursor_down()

    def action_select_all(self) -> None:
        if len(self._selected) == len(self._groups):
            self._selected.clear()
        else:
            self._selected = {g.domain for g in self._groups}
        self._rebuild_table()

    def action_select_visible(self) -> None:
        table = self.query_one(DataTable)
        first = int(table.scroll_y)
        last = min(first + table.size.height - 1, len(self._groups))  # -1 for header
        display = self._sorted_groups()
        visible = {display[i].domain for i in range(first, last)}
        if visible <= self._selected:
            self._selected -= visible
        else:
            self._selected |= visible
        self._rebuild_table()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _target_groups(self) -> list[GroupStatistics]:
        return [g for g in self._groups if g.domain in self._selected]

    def _sender_label(self, group: GroupStatistics) -> str:
        if group.messages:
            m = group.messages[0]
            return m.sender.display_name or m.sender.email or group.domain
        return group.domain

    def _format_target_names(self, targets: list[GroupStatistics]) -> str:
        MAX = 10
        names = [self._sender_label(g) for g in targets[:MAX]]
        result = "\n  · ".join(names)
        if len(targets) > MAX:
            result += f"\n  · … and {len(targets) - MAX} more"
        return result

    def action_search_in_gmail(self) -> None:
        domain = self._cursor_domain()
        if domain is None:
            return
        group = next((g for g in self._groups if g.domain == domain), None)
        if not group or not group.messages:
            return
        email = group.messages[0].sender.email
        query = urllib.parse.quote(f"from:{email}", safe="")
        webbrowser.open(f"https://mail.google.com/mail/u/0/#search/{query}")

    def action_view_in_browser(self) -> None:
        domain = self._cursor_domain()
        if domain is None:
            return
        group = next((g for g in self._groups if g.domain == domain), None)
        if not group or not group.messages:
            return
        msg_id = group.messages[0].id
        webbrowser.open(f"https://mail.google.com/mail/u/0/#all/{msg_id}")

    def action_delete(self) -> None:
        targets = self._target_groups()
        if not targets:
            self._set_status("Nothing to delete.", kind="error")
            return
        total = sum(len(g.messages) for g in targets)
        names = self._format_target_names(targets)
        acted_domains = {g.domain for g in targets}
        self.push_screen(
            ConfirmScreen(f"Delete {total} email{'s' if total != 1 else ''} from:\n  · {names}?"),
            callback=lambda ok: self._exec_delete(targets, acted_domains, ok),
        )

    def _exec_delete(
        self, targets: list[GroupStatistics], acted_domains: set[str], ok: bool | None
    ) -> None:
        if not ok:
            return
        all_ids = [m.id for g in targets for m in g.messages]
        total_del = len(all_ids)
        screen = ProgressScreen(f"Deleting 0/{total_del} emails…")

        def worker() -> set[str]:
            def _progress(trashed: int, total: int) -> None:
                self.call_from_thread(screen.update, f"Deleting {trashed}/{total} emails…")
            self._unsubscribe.trash_messages(all_ids, on_progress=_progress)
            self.call_from_thread(screen.dismiss)
            return acted_domains

        self.push_screen(screen)
        self.run_worker(worker, exclusive=False, thread=True, name="delete")

    def _alias_warning(self, targets: list[GroupStatistics]) -> str:
        """Return a warning line if any target was delivered to a non-primary alias."""
        if not self._gmail_repo:
            return ""
        try:
            primary = self._gmail_repo.get_primary_email()
            send_as = self._gmail_repo.get_send_as_addresses()
        except Exception:
            return ""
        warnings = []
        for g in targets:
            unsub_msg = next((m for m in g.messages if m.has_unsubscribe), None)
            if not unsub_msg or not unsub_msg.delivered_to:
                continue
            addr = unsub_msg.delivered_to
            if addr == primary:
                continue
            if addr in send_as:
                warnings.append(f"  [dim]→ will send as {addr}[/dim]")
            else:
                warnings.append(f"  [yellow]⚠ {addr} has no Send As alias — may need manual unsubscribe[/yellow]")
        return "\n" + "\n".join(warnings) if warnings else ""

    def action_unsubscribe(self) -> None:
        targets = self._target_groups()
        if not targets:
            self._set_status("Nothing to unsubscribe from.", kind="error")
            return
        names = self._format_target_names(targets)
        warning = self._alias_warning(targets)
        msg = f"Unsubscribe from:\n  · {names}?{warning}"
        acted_domains = {g.domain for g in targets}
        self.push_screen(
            ConfirmScreen(msg),
            callback=lambda ok: self._confirm_delete_after_unsub(targets, acted_domains, ok),
        )

    def _confirm_delete_after_unsub(
        self, targets: list[GroupStatistics], acted_domains: set[str], ok: bool | None
    ) -> None:
        if not ok:
            return
        total = sum(len(g.messages) for g in targets)
        self.push_screen(
            ConfirmScreen(f"Also delete {total} email{'s' if total != 1 else ''}?"),
            callback=lambda delete: self._exec_unsubscribe(targets, acted_domains, delete),
        )

    def _exec_unsubscribe(
        self, targets: list[GroupStatistics], acted_domains: set[str], delete: bool | None
    ) -> None:
        total_unsub = len(targets)
        screen = ProgressScreen(f"Unsubscribing 0/{total_unsub}…")

        def _resolve_from(msg) -> str | None:
            if not self._gmail_repo or not msg.delivered_to:
                return None
            try:
                primary = self._gmail_repo.get_primary_email()
                if msg.delivered_to == primary:
                    return None
                send_as = self._gmail_repo.get_send_as_addresses()
                return msg.delivered_to if msg.delivered_to in send_as else None
            except Exception:
                return None

        def worker() -> tuple:
            done = 0
            for i, group in enumerate(targets, 1):
                self.call_from_thread(screen.update, f"Unsubscribing {i}/{total_unsub}…")
                unsub_msg = next((m for m in group.messages if m.has_unsubscribe), None)
                if unsub_msg:
                    try:
                        from_email = _resolve_from(unsub_msg)
                        self._unsubscribe.execute_on_message(unsub_msg, from_email=from_email)
                        all_ids = [m.id for m in group.messages]
                        remaining = [mid for mid in all_ids if mid != unsub_msg.id]
                        if self._unsubscribe.message_store:
                            if remaining:
                                self._unsubscribe.message_store.delete_messages(remaining)
                            self._unsubscribe.message_store.add_excluded_ids(all_ids)
                        done += 1
                    except Exception as e:
                        logger.warning(f"Unsubscribe failed for {group.domain}: {e}")
            if delete:
                all_ids = [m.id for g in targets for m in g.messages]
                total_del = len(all_ids)
                def _del_progress(trashed: int, total: int) -> None:
                    self.call_from_thread(screen.update, f"Deleting {trashed}/{total} emails…")
                _del_progress(0, total_del)
                self._unsubscribe.trash_messages(all_ids, on_progress=_del_progress)
            self.call_from_thread(screen.dismiss)
            return done, acted_domains

        self.push_screen(screen)
        self.run_worker(worker, exclusive=False, thread=True, name="unsubscribe")

    def action_ignore(self) -> None:
        targets = self._target_groups()
        if not targets:
            self._set_status("Nothing to ignore.", kind="error")
            return
        names = self._format_target_names(targets)
        msg = f"Ignore:\n  · {names}?"
        acted_domains = {g.domain for g in targets}
        self.push_screen(
            ConfirmScreen(msg),
            callback=lambda ok: self._exec_ignore(targets, acted_domains, ok),
        )

    def _exec_ignore(
        self, targets: list[GroupStatistics], acted_domains: set[str], ok: bool | None
    ) -> None:
        if not ok:
            return

        def worker() -> tuple:
            done = 0
            for group in targets:
                group_ok = False
                sender_email = group.messages[0].sender.email if group.messages else ''
                for msg in group.messages:
                    try:
                        self._unsubscribe.execute_ignore(
                            msg.id, sender_email=sender_email, domain=group.domain
                        )
                        group_ok = True
                    except Exception as e:
                        logger.warning(f"Ignore failed for {msg.id}: {e}")
                if group_ok:
                    done += 1
            return done, acted_domains

        self.run_worker(worker, exclusive=False, thread=True, name="ignore")

    def action_refresh(self) -> None:
        self._selected.clear()
        if self._gmail_syncer:
            self._set_status("Syncing…")
            self.run_worker(self._sync_then_load, exclusive=True, thread=True, name="fetch")
        else:
            self._load_data()

    def _sync_then_load(self) -> tuple:
        if self._gmail_syncer:
            self._gmail_syncer.sync()
        return self._list_messages.execute_raw(show_all=self._show_all)

    def action_cycle_sort(self) -> None:
        idx = _SORT_CYCLE.index(self._sort_key)
        self._sort_key = _SORT_CYCLE[(idx + 1) % len(_SORT_CYCLE)]
        self._rebuild_table()
        self._set_status(f"Sorted by {_SORT_LABELS[self._sort_key]}")

    def action_ignored_screen(self) -> None:
        if self._message_store:
            self.push_screen(IgnoredScreen(self._message_store))

    def action_help_screen(self) -> None:
        self.push_screen(HelpScreen())
