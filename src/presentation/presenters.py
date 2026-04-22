"""Console presenter."""

import logging
from contextlib import AbstractContextManager

from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.table import Table, box

from ..domain.models.statistics import GroupStatistics
from .interfaces import IPresenter
from .view_models import MessageTableViewModel

logger = logging.getLogger(__name__)


class ConsolePresenter(IPresenter):
    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self._error_style = Style(color="red", bold=True)
        self._success_style = Style(color="green", bold=True)

    def present_messages(self, groups: list[GroupStatistics], seen_domains: set[str]) -> None:
        try:
            view_model = MessageTableViewModel(groups, seen_domains)
            table = Table(
                box=box.SIMPLE,
                show_header=True,
                header_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
                collapse_padding=True,
            )
            table.add_column("#", justify="right", style="cyan", width=3)
            table.add_column("From", justify="left", width=30)
            table.add_column("Subject", justify="left", width=46)
            table.add_column("Age", justify="right", style="dim", width=9)
            table.add_column("Stats", justify="right", style="cyan", width=12)

            for idx, row in enumerate(view_model.rows):
                style = "bold" if row.is_unread else "dim"
                table.add_row(str(idx + 1), row.sender, row.subject, row.age, row.stats, style=style)

            stats_text = (
                f"Total Messages: [cyan]{view_model.total_messages}[/cyan] "
                f"([cyan]{view_model.unread_messages}[/cyan] unread, "
                f"[cyan]{view_model.unread_percent}%[/cyan] unread)\n"
                f"Total Domains: [cyan]{view_model.total_domains}[/cyan]"
            )
            self.console.print(Panel(table, title=stats_text, expand=True))
            self.console.print(
                "  [cyan]<#>u[/cyan] unsub  [cyan]<#>i[/cyan] ignore  "
                "[cyan]n[/cyan]/[cyan]p[/cyan] next/prev  [cyan]?[/cyan] help  [cyan]q[/cyan] quit",
                highlight=False,
            )
        except Exception as e:
            logger.error(f"Error presenting messages: {e}")
            self.present_error(str(e))

    def present_error(self, message: str) -> None:
        self.console.print(f"Error: {message}", style=self._error_style)

    def present_success(self, message: str) -> None:
        self.console.print(message, style=self._success_style)

    def loading(self, message: str) -> AbstractContextManager:
        return self.console.status(message, spinner="dots")
