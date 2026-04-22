# Contributing to MailScrub

## Development Setup

```bash
git clone https://github.com/brooksc/MailScrub.git
cd MailScrub
uv sync
```

Tests do not require Gmail credentials — they use fakes in `tests/test_credentials.json`.

```bash
uv run pytest tests/ -q
uv run ruff check src/ tests/ MailScrub
```

## Credential Safety

**Never commit credentials.** The `.gitignore` blocks the known paths, but
always double-check with `git status` before pushing. If you accidentally
commit a credential, rotate it immediately in the Google Cloud Console.

## Architecture

```
src/
  application/    # use cases — orchestration only, no business logic
  domain/         # models, interfaces, pure business logic
  infrastructure/ # Gmail API, SQLite, HTTP unsubscribe client
  presentation/   # view models, console presenter
  ui/             # Textual TUI and legacy console UI
  di/             # dependency injection container
```

The domain layer has no external dependencies. Infrastructure implements
domain interfaces. Use cases wire them together via the DI container.

## Running Tests

```bash
uv run pytest tests/ -q          # all tests
uv run pytest tests/test_domain.py -v   # one file
```

## Linting

```bash
uv run ruff check src/ tests/ MailScrub
uv run ruff format src/ tests/ MailScrub  # auto-format
```

## Pull Requests

- One feature or fix per PR
- Add or update tests for any changed behaviour
- `ruff check` must pass with no errors
- Keep the `~/.config/mailscrub/` data model in mind — changes to the DB schema
  need migration blocks in `src/infrastructure/database.py`
