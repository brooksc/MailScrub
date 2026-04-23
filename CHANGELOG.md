# Changelog

## [0.1.1] — 2026-04-23

## [0.1.0] — 2026-04-22

Initial public release.

---

### Bug Fixes

- **Alias detection** — `Delivered-To` and `To` headers are now fetched from the Gmail API during
  batch sync. The `Delivered-To` header (set by Gmail's delivery layer) is preferred over `To`
  (set by the sender), so emails addressed to a Gmail alias are correctly identified. A
  `--full-sync` run is needed once to backfill existing messages.

- **Unsubscribe flow split** — senders with a `List-Unsubscribe` header and those without are now
  handled in two separate passes. Previously, senders lacking the header were silently skipped;
  now you are prompted to open browser tabs for each one so you can unsubscribe manually.

- **Delete count accuracy** — the "Also delete N emails?" prompt now counts only the messages from
  senders that *can* be processed automatically (those with an unsubscribe link), not from
  browser-only senders whose emails stay in the table until you decide what to do with them.

- **Local store drift on trash failure** — messages are now removed from the local store only when
  the Gmail trash API call succeeds. Previously, all selected message IDs were removed regardless
  of whether the API call failed, causing the local cache to diverge from Gmail.

- **`execute_on_message` return value** — the method now returns `True` on success and `False` on
  failure instead of `None`, so callers can react to individual unsubscribe failures and
  accurately count how many succeeded vs. failed.

### UX Improvements

- **Empty-inbox state** — when there are no senders left to process, the table area now shows a
  centred message instead of a blank screen:
  - *"No messages found. Press **r** to sync."* — local store is empty (sync may not have run yet).
  - *"All done! Nothing left to process. Press **a** to show all · **r** to sync."* — all senders
    have been unsubscribed, ignored, or deleted.

- **"All done!" on completion** — after an unsubscribe, ignore, or delete action empties the
  sender list, the status bar appends *"All done!"* to the success message.

- **Unsubscribe failure reporting** — individual unsubscribe failures are now counted and reported
  in the status bar (e.g. *"Unsubscribed from 4 sender(s). 1 failed."*) rather than being
  silently discarded.

### Testing

- Added 186 new tests across all layers, bringing total coverage to 203 tests:
  - `test_application.py` — `ListMessagesUseCase.execute_raw` reappeared-sender detection,
    `UnsubscribeUseCase.trash_messages` partial-failure and store-update behaviour,
    `execute_on_message` return values.
  - `test_domain.py` — `DomainService.normalize_domain` with email-address input,
    shared-platform group splitting (Substack-style vs. Amazon-style).
  - `test_infrastructure.py` — `ConfigManager` multi-account methods, `MessageStore` exclusion
    filter, ignored-sender management, sync-state persistence, dismissed-reappeared round-trip,
    `StatusRepository` unsubscribe history, `Delivered-To` header preference.
  - `test_syncer.py` *(new)* — `GmailSyncer.sync` incremental query construction, full-sync
    clearing, `KeyboardInterrupt` handling, `on_progress` callback, `last_sync_at` persistence.
  - `test_unsubscribe_logic.py` — `UnsubscribeClient.send_unsubscribe_email` with bare address,
    `mailto:` URI params, `from_addr`, missing Gmail repo, and API exception handling.
  - `test_entrypoint.py` *(new)* — entry-point functions `_maybe_migrate_legacy`,
    `_pick_account`, and `_resolve_user`.
