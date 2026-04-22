# MailScrub

A terminal UI for finding and bulk-unsubscribing from Gmail newsletters.

MailScrub syncs your Gmail locally, groups emails by sender, and lets you
unsubscribe or delete whole batches in a few keystrokes — without touching
the Gmail web UI.

![MailScrub demo](demo.gif)

## Features

- **Fast** — downloads headers once to SQLite; navigation needs no API calls
- **Groups by sender** — domain-based grouping with shared-platform splitting
  (Substack newsletters stay separate; Amazon stays one row)
- **One-key unsubscribe** — follows RFC 2369 `List-Unsubscribe`: HTTP POST →
  GET → mailto fallback
- **Alias-aware** — detects emails delivered to a non-primary address and uses
  Gmail "Send As" for mailto unsubscribes
- **History tracking** — alerts if a sender reappears after you unsubscribed
- **Ignore / restore** — hide senders locally without deleting from Gmail

## Requirements

- Python 3.10 or later
- [uv](https://docs.astral.sh/uv/) (or pip)
- A Google Cloud project with the Gmail API enabled and an OAuth 2.0 Desktop client

## Quick Start

```bash
git clone https://github.com/brooksc/MailScrub.git
cd MailScrub
uv sync

# Put your credentials in place (see Google Cloud Setup below)
mkdir -p ~/.config/mailscrub/credentials
cp /path/to/downloaded/client_secret_*.json ~/.config/mailscrub/credentials/credentials.json

./MailScrub --new   # OAuth browser login + initial sync
./MailScrub         # Launch TUI (incremental sync on each start)
```

---

## Google Cloud Setup

MailScrub requires a **personal** OAuth 2.0 client — you supply your own so
your credentials are never shared with anyone. The steps below take about
10 minutes.

### Option A — Manual (works for everyone)

#### 1. Create a Google Cloud project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Click the project selector at the top → **New project**
3. Name it `mailscrub` (or anything you like) and click **Create**

#### 2. Enable the Gmail API

1. In the left sidebar: **APIs & Services → Library**
2. Search for **Gmail API** and click **Enable**

#### 3. Configure the OAuth consent screen

1. **APIs & Services → OAuth consent screen**
2. Choose **External** and click **Create**
3. Fill in:
   - **App name**: `MailScrub`
   - **User support email**: your Gmail address
   - **Developer contact email**: your Gmail address
4. Click **Save and Continue** through the Scopes and Test Users screens
   (defaults are fine)
5. On the summary page, click **Back to Dashboard**

> **Note:** Google will show an "unverified app" warning when you log in.
> This is expected for personal-use apps — the OAuth client lives in *your* Cloud project and is scoped only to your own account. Click **Advanced → Go to MailScrub (unsafe)**
> to proceed. Only your own account will ever see this screen.

#### 4. Create OAuth 2.0 credentials

1. **APIs & Services → Credentials**
2. **Create Credentials → OAuth client ID**
3. Application type: **Desktop app**
4. Name: `MailScrub Desktop`
5. Click **Create**, then **Download JSON**
6. Move the file to the MailScrub credentials directory:

```bash
mkdir -p ~/.config/mailscrub/credentials
mv ~/Downloads/client_secret_*.json ~/.config/mailscrub/credentials/credentials.json
```

#### 5. Authenticate

```bash
./MailScrub --new
```

A browser window opens. Log in with your Gmail account and grant the requested
permissions. The OAuth token is saved to `~/.config/mailscrub/tokens/you@gmail.com.json`
and reused on future runs.

---

### Option B — Automated with `gcloud` CLI

If you have the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install)
installed, run the included helper:

```bash
bash setup_gcloud.sh
```

The script creates a Cloud project, enables the Gmail API, creates a Desktop
OAuth client, and writes `credentials.json` to `~/.config/mailscrub/credentials/`.

You can also ask **Claude Code** (with gcloud available) to do it for you:

> *"Set up a Google Cloud OAuth Desktop client for MailScrub. Enable the Gmail
> API and save credentials.json to ~/.config/mailscrub/credentials/credentials.json"*

---

## Usage

```bash
./MailScrub                         # incremental sync + TUI
./MailScrub --new                   # add / re-authenticate a Gmail account
./MailScrub --user you@gmail.com    # use a specific account (multi-account)
./MailScrub --full-sync             # wipe local cache, re-download everything
./MailScrub --no-sync               # skip sync and open TUI immediately
./MailScrub --read-only             # request read-only access (disables unsubscribe/delete)
./MailScrub --debug                 # verbose logging to stderr and debug.log
```

### Key Bindings

| Key | Action |
|-----|--------|
| `Space` | Select / deselect row |
| `a` | Select all |
| `*` | Select all visible |
| `u` | Unsubscribe from selected senders |
| `d` | Delete emails from selected senders |
| `i` | Ignore selected senders (hides locally, no Gmail change) |
| `f` | Forget unsubscribe record (re-enables reappeared alert) |
| `v` | View sender in Gmail (browser) |
| `s` | Search sender in Gmail (browser) |
| `o` | Cycle sort: message count → sender name → newest first |
| `r` | Refresh / incremental sync |
| `e` | View ignored senders (and optionally restore) |
| `?` | Help |
| `q` | Quit |

---

## How It Works

1. **Sync** — On startup, MailScrub queries Gmail for:
   ```
   {category:promotions unsubscribe} -in:trash -in:sent -in:spam -is:starred
   ```
   and downloads message headers (not bodies) to a local SQLite database.

2. **Group** — Messages are grouped by sending domain. Shared platforms
   (Substack, Beehiiv) are split per newsletter based on sender display name;
   brands that use multiple sending addresses (Amazon) are kept as one row.

3. **Unsubscribe** — Follows the `List-Unsubscribe` header:
   - HTTP POST (if `List-Unsubscribe-Post` header is present)
   - HTTP GET fallback
   - `mailto:` as last resort (sends an email via Gmail API)

4. **Alias detection** — If an email was delivered to a non-primary address
   that is configured as a Gmail "Send As" alias, unsubscribe emails are sent
   from that alias rather than your primary address.

---

## Data Storage

Everything lives in `~/.config/mailscrub/` — nothing is written to the project directory:

```
~/.config/mailscrub/
├── config.json                     # account registry and path overrides
├── credentials/
│   └── credentials.json            # YOUR Google OAuth client (you supply this)
├── tokens/
│   └── you@gmail.com.json          # OAuth access/refresh token (auto-created per account)
└── you@gmail.com.db                # local email header cache (auto-created per account)
```

Multiple accounts each get their own token and database file.
When you run `./MailScrub` with more than one account registered, a numbered
menu lets you pick which account to open.

Because all data lives in `~/.config/mailscrub/`, you can `git pull` to update
MailScrub at any time without affecting your credentials or sync history.

---

## Privacy

MailScrub stores **email headers only** (sender, subject, date, and the
`List-Unsubscribe` header value) in a local SQLite file on your own machine.
No data is sent to any third-party service. Unsubscribe requests go directly
from your machine to the sender's endpoint.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
