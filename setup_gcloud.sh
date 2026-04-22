#!/usr/bin/env bash
# setup_gcloud.sh — bootstrap a Google Cloud project for MailScrub
#
# Requires: gcloud CLI installed and authenticated (`gcloud auth login`)
#
# What this does:
#   1. Creates a new Cloud project
#   2. Enables the Gmail API
#   3. Creates a Desktop OAuth 2.0 client
#   4. Writes credentials.json to ~/.config/mailscrub/credentials/
#
# After this script completes, run:  ./MailScrub --new
set -euo pipefail

DEST="$HOME/.config/mailscrub/credentials/credentials.json"

# ── Preflight checks ──────────────────────────────────────────────────────────

if ! command -v gcloud &>/dev/null; then
  echo "Error: gcloud CLI not found."
  echo "Install it from: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

if [[ -f "$DEST" ]]; then
  echo "credentials.json already exists at $DEST"
  echo "Delete it first if you want to create a new one."
  exit 0
fi

ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
if [[ -z "$ACCOUNT" ]]; then
  echo "Not logged in to gcloud. Run: gcloud auth login"
  exit 1
fi

echo "Logged in as: $ACCOUNT"
echo ""

# ── Create project ────────────────────────────────────────────────────────────

PROJECT_ID="mailscrub-$(date +%s)"
echo "Creating project $PROJECT_ID …"
gcloud projects create "$PROJECT_ID" --name="MailScrub" --quiet
gcloud config set project "$PROJECT_ID" --quiet

echo ""
echo "If you have a billing account, you may want to link it now."
echo "Some APIs require billing even on the free tier."
echo "(Press Enter to continue without billing, or Ctrl-C to abort and link billing first.)"
read -r

# ── Enable Gmail API ──────────────────────────────────────────────────────────

echo "Enabling Gmail API …"
gcloud services enable gmail.googleapis.com --quiet
echo "Gmail API enabled."

# ── OAuth consent screen ──────────────────────────────────────────────────────

echo ""
echo "Configuring OAuth consent screen …"
# The gcloud CLI cannot fully automate the consent screen; open the URL for the user.
CONSENT_URL="https://console.cloud.google.com/apis/credentials/consent?project=$PROJECT_ID"
echo ""
echo "Please complete the OAuth consent screen in your browser:"
echo "  $CONSENT_URL"
echo ""
echo "  1. Choose 'External' and click Create"
echo "  2. Fill in App name (MailScrub) and your email, then Save and Continue"
echo "  3. Skip Scopes and Test Users (just click Save and Continue)"
echo ""
echo "Press Enter once the consent screen is saved …"
open "$CONSENT_URL" 2>/dev/null || xdg-open "$CONSENT_URL" 2>/dev/null || true
read -r

# ── Create OAuth client ───────────────────────────────────────────────────────

echo "Creating OAuth Desktop client …"
CREDS_URL="https://console.cloud.google.com/apis/credentials/oauthclient?project=$PROJECT_ID"
echo ""
echo "Please create an OAuth client in your browser:"
echo "  $CREDS_URL"
echo ""
echo "  1. Application type: Desktop app"
echo "  2. Name: MailScrub Desktop"
echo "  3. Click Create, then Download JSON"
echo "  4. Save the downloaded file as:"
echo "       $DEST"
echo ""
open "$CREDS_URL" 2>/dev/null || xdg-open "$CREDS_URL" 2>/dev/null || true
echo "Press Enter once you have saved credentials.json to $DEST …"
read -r

# ── Verify ────────────────────────────────────────────────────────────────────

mkdir -p "$(dirname "$DEST")"

if [[ -f "$DEST" ]]; then
  echo ""
  echo "✓ credentials.json found at $DEST"
  echo ""
  echo "Next step: ./MailScrub --new"
else
  echo ""
  echo "credentials.json not found at $DEST"
  echo "Make sure you downloaded and moved the file before proceeding."
  exit 1
fi
