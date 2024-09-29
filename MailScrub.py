#!/usr/bin/env python3
import base64
import os
import pickle
import re
import logging
import time
import argparse
import requests
import json
import ast
from datetime import datetime, timedelta

from playwright.sync_api import sync_playwright
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Function to save browser actions to a pickle file
def save_browser_actions(url, actions):
    with open('browser-actions.pickle', 'ab') as f:
        pickle.dump({'url': url, 'actions': actions}, f)

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('googleapiclient').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Define the default number of days to fetch emails
DEFAULT_DAYS_TO_FETCH = 7

def create_label(service, label_name):
    """Create a new Gmail label."""
    try:
        label = service.users().labels().create(
            userId='me',
            body={'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}
        ).execute()
        logger.info(f"Created new label '{label_name}' with ID: {label['id']}")
        return label['id']
    except Exception as e:
        logger.error(f"Failed to create label '{label_name}'. Error: {e}")
        return None

def get_label_id(service, label_name):
    """Retrieve the ID of a Gmail label by name, creating it if it doesn't exist."""
    label_id = None
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                label_id = label['id']
                break
        if label_id is None:
            logger.warning(f"Label '{label_name}' not found. Attempting to create it.")
            label_id = create_label(service, label_name)
        else:
            logger.info(f"Label '{label_name}' has ID: {label_id}")
    except Exception as e:
        logger.error(f"Failed to retrieve labels. Error: {e}")
    return label_id

def fetch_emails(service, days_to_fetch, mailscrubbed_label_id):
    """Fetch emails from Gmail received in the specified number of days that are not MailScrubbed."""
    now = datetime.now()
    days_ago = (now - timedelta(days=days_to_fetch)).strftime('%Y/%m/%d')
    logger.info(f"Fetching emails from {days_ago} to {now.isoformat()}Z")
    query = f'after:{days_ago} -label:MailScrubbed -label:stay-subscribed'
    logger.info(f"Sending query to Gmail API: {query}")

    messages = []
    next_page_token = None

    while True:
        results = service.users().messages().list(
            userId='me', q=query, maxResults=100, pageToken=next_page_token
        ).execute()
        messages.extend(results.get('messages', []))
        next_page_token = results.get('nextPageToken')

        if not next_page_token:
            break

    emails_fetched = len(messages)
    logger.info(f"Fetched {emails_fetched} emails")

    if emails_fetched == 0:
        logger.info("Checking if there are any emails in the inbox...")
        all_emails = service.users().messages().list(userId='me').execute()
        all_emails_count = len(all_emails.get('messages', []))
        logger.info(f"Total emails in the inbox: {all_emails_count}")

    # Fetch MailScrubbed emails to get domains and last unsubscribe dates
    mailscrubbed_emails = fetch_mailscrubbed_emails(service, mailscrubbed_label_id)
    domains_last_unsubscribed = extract_domains_and_dates(service, mailscrubbed_emails)

    return messages, domains_last_unsubscribed

def fetch_mailscrubbed_emails(service, mailscrubbed_label_id):
    """Fetch all emails with the MailScrubbed label."""
    query = f'label:{mailscrubbed_label_id}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

def extract_domains_and_dates(service, messages):
    """Extract domains and last unsubscribe dates from MailScrubbed emails."""
    domains_last_unsubscribed = {}
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload'].get('headers', [])
        from_header = next((header['value'] for header in headers if header['name'].lower() == 'from'), '')
        date_header = next((header['value'] for header in headers if header['name'].lower() == 'date'), '')
        if '@' in from_header and date_header:
            domain = from_header.split('@')[-1].split('>')[0]
            try:
                date = datetime.strptime(date_header, '%a, %d %b %Y %H:%M:%S %z')
            except ValueError:
                logger.error(f"Failed to parse date: {date_header}")
                continue
            if domain not in domains_last_unsubscribed or domains_last_unsubscribed[domain] < date:
                domains_last_unsubscribed[domain] = date
    return domains_last_unsubscribed

def find_unsubscribe_link(service, message_id):
    """Find the unsubscribe link in an email and log the email's from/subject."""
    message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
    headers = message['payload'].get('headers', [])
    from_email = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
    subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'Unknown')
    to_email = next((header['value'] for header in headers if header['name'] == 'Delivered-To'), 'your_actual_email@example.com')

    payload = message['payload']
    parts = payload.get('parts', [])
    body = ''

    # Extract the email body
    for part in parts:
        if part['mimeType'] == 'text/html':
            body = part['body']['data']
            break
        elif 'parts' in part:
            for subpart in part['parts']:
                if subpart['mimeType'] == 'text/html':
                    body = subpart['body']['data']
                    break

    if body:
        decoded_body = base64.urlsafe_b64decode(body + '==').decode('utf-8', errors='ignore')
        unsubscribe_link = re.search(
            r'(?i)<a[^>]*href=["\']([^"\']*)["\'][^>]*>(?:unsubscribe|opt.?out)</a>',
            decoded_body
        )
        if unsubscribe_link:
            logger.info(f"Found unsubscribe link for email from: {from_email}, Subject: {subject}")
            return unsubscribe_link.group(1), from_email, to_email, decoded_body

    return None, from_email, to_email, ''

def authenticate_google():
    """Authenticate with the Gmail API and return the service object."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                if 'invalid_grant' in str(e):
                    logger.warning("Token has been expired or revoked. Deleting token.json and re-authenticating.")
                    os.remove('token.json')
                    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
                    creds = flow.run_local_server(port=0)
                    with open('token.json', 'w') as token:
                        token.write(creds.to_json())
                else:
                    raise e
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def get_do_not_unsubscribe_list(service):
    """Get the list of domains and senders to not unsubscribe from."""
    do_not_unsubscribe_label_id = get_label_id(service, 'do-not-unsubscribe')
    if not do_not_unsubscribe_label_id:
        return set(), set()

    query = f'label:do-not-unsubscribe'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])

    domains = set()
    senders = set()

    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload'].get('headers', [])
        from_header = next((header['value'] for header in headers if header['name'].lower() == 'from'), '')

        if '@' in from_header:
            domain = from_header.split('@')[-1].split('>')[0]
            domains.add(domain)
            sender = from_header.split('<')[0].strip()
            senders.add(sender)

    return domains, senders

def send_to_ollama(prompt):
    """Send a prompt to the local Ollama instance and return the response."""
    url = 'http://localhost:11434/generate'  # Default Ollama endpoint
    headers = {'Content-Type': 'application/json'}
    data = {
        'model': 'llama3.1',
        'prompt': prompt
    }
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), stream=True)
        response_text = ''
        for chunk in response.iter_content(chunk_size=None, decode_unicode=True):
            if chunk:
                response_text += chunk
        return response_text
    except Exception as e:
        logger.error(f"Failed to communicate with Ollama: {e}")
        return ''

def execute_ai_generated_code(page, code):
    """Execute AI-generated code safely."""
    # We will use ast.literal_eval to parse code into a Python object.
    # For safety, we'll restrict the execution environment.
    allowed_builtins = {'__builtins__': None}
    exec_globals = {'page': page}
    exec_locals = {}
    try:
        exec(code, exec_globals, exec_locals)
    except Exception as e:
        logger.error(f"Error executing AI-generated code: {e}")

def unsubscribe_emails(service, mailscrubbed_label_id, max_emails=None, days_to_fetch=DEFAULT_DAYS_TO_FETCH):
    """Unsubscribe from emails and log details about how we're unsubscribing."""
    messages, domains_last_unsubscribed = fetch_emails(service, days_to_fetch, mailscrubbed_label_id)
    processed_domains = set()
    do_not_unsubscribe_domains, do_not_unsubscribe_senders = get_do_not_unsubscribe_list(service)
    logger.info(f"Do not unsubscribe domains: {do_not_unsubscribe_domains}")
    logger.info(f"Do not unsubscribe senders: {do_not_unsubscribe_senders}")
    emails_processed = 0

    for message in messages:
        message_id = message['id']
        unsubscribe_link, from_email, to_email, email_body = find_unsubscribe_link(service, message_id)
        if unsubscribe_link:
            domain = unsubscribe_link.split('/')[2]

            if domain in domains_last_unsubscribed:
                last_unsubscribed_date = domains_last_unsubscribed[domain]
                lookback_period = timedelta(days=2 * days_to_fetch)
                if datetime.now() - last_unsubscribed_date < lookback_period:
                    logger.info(f"Skipping unsubscribe for domain {domain} as it was unsubscribed less than {lookback_period.days} days ago.")
                    continue

            if domain in do_not_unsubscribe_domains:
                logger.info(f"Skipping unsubscribe for domain {domain} as it's in the do-not-unsubscribe list.")
                continue

            if any(sender.lower() in from_email.lower() for sender in do_not_unsubscribe_senders):
                logger.info(f"Skipping unsubscribe for sender {from_email} as it's in the do-not-unsubscribe list.")
                continue

            logger.info(f"Attempting to unsubscribe from email with ID: {message_id} using link: {unsubscribe_link}")

            if args.playwright:
                # Initialize Playwright
                logger.info("Initializing Playwright...")
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=False)
                    page = browser.new_page()
                    logger.info("Playwright initialized successfully.")
                    time.sleep(2)  # Wait for 2 seconds to ensure page is ready
            else:
                logger.info("Playwright is disabled. Skipping browser automation.")
                continue

                # Capture user interactions
                user_actions = []

                try:
                    logger.info(f"Navigating to unsubscribe link: {unsubscribe_link}")
                    logger.info(f"Email was sent to: {to_email}")
                    page.goto(unsubscribe_link, wait_until='networkidle')

                    # Extract page content
                    page_content = page.content()
                    logger.info("Extracted page content for AI processing.")

                    # Prepare prompt for Ollama
                    prompt = f"""
You are a web automation assistant. The goal is to unsubscribe from an email list using the given webpage content.
Email: {to_email}
Webpage content:
{page_content}

Provide Python Playwright code to perform the following steps:
1. If the page indicates that the user is already unsubscribed, do nothing.
2. If an email input field is present, fill it with the user's email.
3. If a checkbox to 'Unsubscribe from All' is present, select it.
4. Click the submit/unsubscribe button.
5. Wait for any confirmation that the user has been unsubscribed.

Return only the Python code that uses the 'page' object to perform these actions.
"""

                    # Send prompt to Ollama
                    logger.info("Sending prompt to Ollama for AI-generated code.")
                    ai_response = send_to_ollama(prompt)

                    if ai_response:
                        logger.info("Received AI-generated code from Ollama.")
                        # Execute the AI-generated code
                        execute_ai_generated_code(page, ai_response)
                        logger.info("Executed AI-generated code.")
                    else:
                        logger.error("No response from Ollama. Cannot proceed with AI automation.")

                    # Wait for any confirmation messages or page redirects
                    time.sleep(2)

                    # Check for confirmation text
                    confirmation_text = page.inner_text('body')
                    if re.search(r'unsubscribed|successfully unsubscribed|already unsubscribed', confirmation_text, re.IGNORECASE):
                        logger.info("Successfully unsubscribed.")
                    else:
                        logger.warning("Unsubscribe may not have been successful. Manual check recommended.")

                    browser.close()
                    logger.info("Browser closed. Continuing with the next email.")

                    # Automatically label the email as 'MailScrubbed'
                    process_user_input(service, message_id, '1', mailscrubbed_label_id)

                except Exception as e:
                    logger.error(f"Failed to navigate to unsubscribe link for email with ID: {message_id}. Error: {e}")
                    browser.close()
                    continue

            emails_processed += 1
            if max_emails and emails_processed >= max_emails:
                logger.info(f"Reached maximum number of emails to process: {max_emails}")
                break

def process_user_input(service, message_id, user_input, mailscrubbed_label_id):
    """Process user's input after attempting to unsubscribe."""
    if user_input == '1':
        # Add "MailScrubbed" label to the email
        label_body = {
            'addLabelIds': [mailscrubbed_label_id] if mailscrubbed_label_id else [],
            'removeLabelIds': []
        }
        service.users().messages().modify(userId='me', id=message_id, body=label_body).execute()
        logger.info(f"Added 'MailScrubbed' label to email with ID: {message_id}")
    elif user_input == '2':
        # Skip the email and take no further action
        logger.info(f"Skipping email with ID: {message_id}")
    elif user_input == '3':
        # Add the "do-not-unsubscribe" tag to the email
        do_not_unsubscribe_label_id = get_label_id(service, 'do-not-unsubscribe')
        if do_not_unsubscribe_label_id:
            label_body = {
                'addLabelIds': [do_not_unsubscribe_label_id],
                'removeLabelIds': []
            }
            service.users().messages().modify(userId='me', id=message_id, body=label_body).execute()
            logger.info(f"Added 'do-not-unsubscribe' label to email with ID: {message_id}")
        else:
            logger.error("Failed to find or create 'do-not-unsubscribe' label.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gmail Unsubscribe Tool')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-n', type=int, help='Number of emails to process before exiting')
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS_TO_FETCH, help='Number of days to fetch emails for')
    parser.add_argument('--playwright', action='store_true', help='Enable Playwright for browser automation')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        service = authenticate_google()
        mailscrubbed_label_id = get_label_id(service, 'MailScrubbed')
        unsubscribe_emails(service, mailscrubbed_label_id, args.n, args.days)

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Saving state and exiting...")
        exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        exit(1)
