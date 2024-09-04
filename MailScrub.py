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

# Define the number of days to fetch emails
DAYS_TO_FETCH = 7

# Define the path for the config file
CONFIG_FILE = os.path.expanduser('~/.gmail_unsubscribe')

def load_config():
    """Load the configuration from the config file."""
    config = {'domains': set(), 'senders': set()}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                key, value = line.strip().split(':', 1)
                config[key] = set(value.split(','))
    logger.debug(f"Loaded config: {config}")
    return config

def save_config(config):
    """Save the configuration to the config file."""
    with open(CONFIG_FILE, 'w') as f:
        for key, value in config.items():
            f.write(f"{key}:{','.join(value)}\n")

def edit_config(args):
    """Edit the configuration based on command line arguments."""
    config = load_config()
    if args.domain:
        config['domains'].update(args.domain)
    if args.sender:
        config['senders'].update(args.sender)
    save_config(config)
    logger.debug("Configuration updated and saved.")

"""Authenticate with the Gmail API and return the service object."""
creds = None
if os.path.exists('token.pickle'):
    with open('token.pickle', 'rb') as token:
        creds = pickle.load(token)
if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    with open('token.pickle', 'wb') as token:
        pickle.dump(creds, token)

def get_label_id(service, label_name):
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

def fetch_emails(service):
    """Fetch emails from Gmail received in the last 7 days that are not processed."""
    now = datetime.now()
    days_ago = (now - timedelta(days=DAYS_TO_FETCH)).strftime('%Y/%m/%d')
    logger.debug(f"Fetching emails from {days_ago} to {now.isoformat()}Z")
    query = f'after:{days_ago} -label:processed -label:stay-subscribed'
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

    return messages

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
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def unsubscribe_emails(service, processed_label_id, max_emails=None):
    """Unsubscribe from emails and log details about how we're unsubscribing."""
    messages = fetch_emails(service)
    processed_domains = set()
    config = load_config()
    logger.debug(f"Config loaded: {config}")
    emails_processed = 0
    for message in messages:
        message_id = message['id']
        unsubscribe_link, from_email, to_email = find_unsubscribe_link(service, message_id)
        if unsubscribe_link:
            domain = unsubscribe_link.split('/')[2]

            if domain in processed_domains:
                logger.debug(f"Skipping unsubscribe for domain {domain} as it has already been processed.")
                continue

            if domain in config['domains']:
                logger.debug(f"Skipping unsubscribe for domain {domain} as it's in the skip list.")
                continue

            if any(sender.lower() in from_email.lower() for sender in config['senders'] if sender):
                logger.debug(f"Skipping unsubscribe for sender {from_email} as it's in the skip list.")
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
                logger.debug(f"Added domain {domain} to processed domains.")

            except Exception as e:
                logger.error(f"Failed to navigate to unsubscribe link for email with ID: {message_id}. Error: {e}")
            finally:
                try:
                    driver.quit()
                except:
                    pass

            # Add "processed" label to the email after browser is closed
            label_body = {
                'addLabelIds': [processed_label_id],
                'removeLabelIds': []
            }
            service.users().messages().modify(userId='me', id=message_id, body=label_body).execute()
            logger.debug(f"Added 'processed' label to email with ID: {message_id}")

            emails_processed += 1
            if max_emails and emails_processed >= max_emails:
                logger.info(f"Reached maximum number of emails to process: {max_emails}")
                break

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gmail Unsubscribe Tool')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--domain', action='append', help='Add domain to ignore list')
    parser.add_argument('--sender', action='append', help='Add sender email or name to ignore list')
    parser.add_argument('-n', type=int, help='Number of emails to process before exiting')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.domain or args.sender:
        edit_config(args)
        logger.info("Configuration updated. Exiting.")
        exit(0)

    try:
        service = authenticate_google()
        processed_label_id = get_label_id(service, 'processed')
        unsubscribe_emails(service, processed_label_id, args.n)

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Saving state and exiting...")
        exit(0)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        exit(1)
