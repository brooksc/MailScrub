#!/usr/bin/env python3
import base64
import os
import os.path
import pickle
import re
import logging
import time
import argparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from datetime import datetime, timedelta

# If modifying these SCOPES, delete the file token.pickle.
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
        label = service.users().labels().create(userId='me', body={'name': label_name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'}).execute()
        logger.info(f"Created new label '{label_name}' with ID: {label['id']}")
        return label['id']
    except Exception as e:
        logger.error(f"Failed to create label '{label_name}'. Error: {e}")
        return None

def get_label_id(service, label_name):
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
            logger.debug(f"Label '{label_name}' has ID: {label_id}")
    except Exception as e:
        logger.error(f"Failed to retrieve labels. Error: {e}")
    return label_id
    """Retrieve the ID of a Gmail label by name."""
    label_id = None
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label['name'].lower() == label_name.lower():
                label_id = label['id']
                break
        if label_id is None:
            logger.error(f"Label '{label_name}' not found.")
        else:
            logger.debug(f"Label '{label_name}' has ID: {label_id}")
    except Exception as e:
        logger.error(f"Failed to retrieve labels. Error: {e}")
    return label_id

def fetch_emails(service, days_to_fetch, MailScrubbed_label_id):
    """Fetch emails from Gmail received in the specified number of days that are not MailScrubbed."""
    now = datetime.now()
    days_ago = (now - timedelta(days=days_to_fetch)).strftime('%Y/%m/%d')
    logger.debug(f"Fetching emails from {days_ago} to {now.isoformat()}Z")
    query = f'after:{days_ago} -label:MailScrubbed -label:stay-subscribed'
    logger.debug(f"Sending query to Gmail API: {query}")

    messages = []
    next_page_token = None

    while True:
        results = service.users().messages().list(userId='me', q=query, maxResults=100, pageToken=next_page_token).execute()
        messages.extend(results.get('messages', []))
        next_page_token = results.get('nextPageToken')

        if not next_page_token:
            break

    emails_fetched = len(messages)
    logger.debug(f"Fetched {emails_fetched} emails")

    if emails_fetched == 0:
        logger.debug("Checking if there are any emails in the inbox...")
        all_emails = service.users().messages().list(userId='me').execute()
        all_emails_count = len(all_emails.get('messages', []))
        logger.debug(f"Total emails in the inbox: {all_emails_count}")

    # Fetch MailScrubbed emails to get domains and last unsubscribe dates
    mailscrubbed_emails = fetch_mailscrubbed_emails(service, MailScrubbed_label_id)
    domains_last_unsubscribed = extract_domains_and_dates(mailscrubbed_emails)

    return messages, domains_last_unsubscribed

def fetch_mailscrubbed_emails(service, MailScrubbed_label_id):
    """Fetch all emails with the MailScrubbed label."""
    query = f'label:{MailScrubbed_label_id}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

def extract_domains_and_dates(messages):
    """Extract domains and last unsubscribe dates from MailScrubbed emails."""
    domains_last_unsubscribed = {}
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload']['headers']
        from_header = next((header['value'] for header in headers if header['name'].lower() == 'from'), '')
        date_header = next((header['value'] for header in headers if header['name'].lower() == 'date'), '')
        if '@' in from_header:
            domain = from_header.split('@')[-1].split('>')[0]
            date = datetime.strptime(date_header, '%a, %d %b %Y %H:%M:%S %z')
            if domain not in domains_last_unsubscribed or domains_last_unsubscribed[domain] < date:
                domains_last_unsubscribed[domain] = date
    return domains_last_unsubscribed

def find_unsubscribe_link(service, message_id):
    """Find the unsubscribe link in an email and log the email's from/subject."""
    message = service.users().messages().get(userId='me', id=message_id).execute()
    headers = message['payload']['headers']
    from_email = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
    subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'Unknown')
    to_email = next((header['value'] for header in headers if header['name'] == 'To'), 'Unknown')

    payload = message['payload']
    if 'parts' in payload:
        for part in payload['parts']:
            if part['mimeType'] == 'text/html':
                body = part['body']['data']
                decoded_body = base64.urlsafe_b64decode(body).decode('utf-8')
                unsubscribe_link = re.search(r'(?i)<a[^>]*href=["\']([^"\']*)["\'][^>]*>(?:unsubscribe|opt.?out)</a>', decoded_body)
                if unsubscribe_link:
                    logger.debug(f"Found unsubscribe link for email from: {from_email}, Subject: {subject}")
                    return unsubscribe_link.group(1), from_email, to_email
    return None, from_email, to_email

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
        headers = msg['payload']['headers']
        from_header = next((header['value'] for header in headers if header['name'].lower() == 'from'), '')

        if '@' in from_header:
            domain = from_header.split('@')[-1].split('>')[0]
            domains.add(domain)
            sender = from_header.split('<')[0].strip()
            senders.add(sender)

    return domains, senders

def unsubscribe_emails(service, MailScrubbed_label_id, max_emails=None, days_to_fetch=DEFAULT_DAYS_TO_FETCH):
    """Unsubscribe from emails and log details about how we're unsubscribing."""
    messages, domains_last_unsubscribed = fetch_emails(service, days_to_fetch, MailScrubbed_label_id)
    processed_domains = set()
    do_not_unsubscribe_domains, do_not_unsubscribe_senders = get_do_not_unsubscribe_list(service)
    logger.debug(f"Do not unsubscribe domains: {do_not_unsubscribe_domains}")
    logger.debug(f"Do not unsubscribe senders: {do_not_unsubscribe_senders}")
    emails_processed = 0
    for message in messages:
        message_id = message['id']
        unsubscribe_link, from_email, to_email = find_unsubscribe_link(service, message_id)
        if unsubscribe_link:
            domain = unsubscribe_link.split('/')[2]

            if domain in domains_last_unsubscribed:
                last_unsubscribed_date = domains_last_unsubscribed[domain]
                lookback_period = timedelta(days=2 * days_to_fetch)
                if datetime.now() - last_unsubscribed_date < lookback_period:
                    logger.debug(f"Skipping unsubscribe for domain {domain} as it was unsubscribed less than {lookback_period.days} days ago.")
                    continue
                logger.debug(f"Skipping unsubscribe for domain {domain} as it has already been processed.")
                continue

            if domain in do_not_unsubscribe_domains:
                logger.debug(f"Skipping unsubscribe for domain {domain} as it's in the do-not-unsubscribe list.")
                continue

            if any(sender.lower() in from_email.lower() for sender in do_not_unsubscribe_senders):
                logger.debug(f"Skipping unsubscribe for sender {from_email} as it's in the do-not-unsubscribe list.")
                continue

            logger.debug(f"Attempting to unsubscribe from email with ID: {message_id} using link: {unsubscribe_link}")

            # Initialize the WebDriver (assuming ChromeDriver is in PATH)
            logger.debug("Initializing WebDriver...")
            try:
                driver = webdriver.Chrome()
                logger.debug("WebDriver initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize WebDriver. Error: {e}")
                continue

            try:
                logger.debug(f"Navigating to unsubscribe link: {unsubscribe_link}")
                logger.debug(f"Email was sent to: {to_email}")
                driver.get(unsubscribe_link)

                logger.debug("Waiting for browser to be closed...")
                while len(driver.window_handles) > 0:
                    time.sleep(1)
                logger.debug("Browser closed. Continuing with the next email.")

                processed_domains.add(domain)
                logger.debug(f"Added domain {domain} to MailScrubbed domains.")

            except Exception as e:
                logger.error(f"Failed to navigate to unsubscribe link for email with ID: {message_id}. Error: {e}")
            finally:
                try:
                    driver.quit()
                except:
                    pass

            # Add "MailScrubbed" label to the email after browser is closed
            label_body = {
                'addLabelIds': [MailScrubbed_label_id] if MailScrubbed_label_id else [],
                'removeLabelIds': []
            }
            service.users().messages().modify(userId='me', id=message_id, body=label_body).execute()
            logger.debug(f"Added 'MailScrubbed' label to email with ID: {message_id}")

            emails_processed += 1
            if max_emails and emails_processed >= max_emails:
                logger.info(f"Reached maximum number of emails to process: {max_emails}")
                break

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gmail Unsubscribe Tool')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-n', type=int, help='Number of emails to process before exiting')
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS_TO_FETCH, help='Number of days to fetch emails for')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        service = authenticate_google()
        MailScrubbed_label_id = get_label_id(service, 'MailScrubbed')
        unsubscribe_emails(service, MailScrubbed_label_id, args.n, args.days)

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Saving state and exiting...")
        exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        exit(1)
