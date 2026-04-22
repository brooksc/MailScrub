# Security

## OAuth scope

MailScrub requests `https://www.googleapis.com/auth/gmail.modify`, which allows
reading, labelling, and deleting messages but **not** sending email on your
behalf (except for `mailto:` unsubscribe replies, which require the scope to
send from aliases).

If you only need to browse and do not plan to unsubscribe or delete, run:

```bash
./MailScrub --new --read-only
```

This grants `gmail.readonly` instead and disables all write actions in the UI.

## Token storage

Your OAuth token is stored locally at:

```
~/.config/mailscrub/tokens/token.json
```

It never leaves your machine. MailScrub does not communicate with any server
other than Google's OAuth endpoints and the unsubscribe URLs embedded in your
own emails.

## Credentials storage

Your Google OAuth client credentials are stored at:

```
~/.config/mailscrub/credentials/credentials.json
```

These are the credentials for *your* Cloud project, not a shared secret. Treat
this file like a password — do not commit it or share it.

## Revoking access

To revoke MailScrub's access to your Gmail account at any time:

1. Go to <https://myaccount.google.com/permissions>
2. Find **MailScrub** and click **Remove Access**

Then delete `~/.config/mailscrub/tokens/token.json` locally.

## Reporting a vulnerability

Open an issue at <https://github.com/brooksc/MailScrub/issues> or email
the maintainer directly. Please do not include sensitive credential data in
bug reports.
