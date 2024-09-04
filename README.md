# Gmail Unsubscribe Tool

This script helps automate the process of unsubscribing from unwanted emails using the Gmail API and Selenium. It scans your inbox for emails received within a specified number of days and attempts to unsubscribe from mailing lists by detecting unsubscribe links within the email body. Emails that are successfully processed are labeled as `MailScrubbed`.

## Features

- Fetches emails from Gmail using the Gmail API.
- Detects unsubscribe links in the email body.
- Uses Selenium to navigate to unsubscribe links and process the unsubscriptions.
- Adds a `MailScrubbed` label to emails after they are processed.
- Skips emails based on a `do-not-unsubscribe` label, allowing certain domains or senders to be excluded from unsubscriptions.
- Supports specifying the number of days to fetch emails from and the maximum number of emails to process.

## Requirements

- Python 3.x
- ChromeDriver installed and added to your `PATH` (required for Selenium)
- Google API Client Libraries
- Gmail API credentials (`credentials.json` file required)

## Setup

1. **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2. **Install the required Python dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3. **Set up Gmail API credentials:**
    - Create a project in the [Google Developer Console](https://console.developers.google.com/).
    - Enable the Gmail API for the project.
    - Download the `credentials.json` file and place it in the root directory of this project.
    - Add your email as a test user

4. **Run the script:**

    ```bash
    python3 MailScrub.py
    ```

    The script will authenticate with your Google account and fetch emails that match the query (by default, emails received within the last 7 days and not labeled `MailScrubbed` or `stay-subscribed`).

## Usage

The script can be run with different command-line arguments:

- **Enable Debug Logging:**

    To see more detailed logs:

    ```bash
    python3 MailScrub.py --debug
    ```

- **Process a Specific Number of Emails:**

    Limit the number of emails processed by using the `-n` flag:

    ```bash
    python3 MailScrub.py -n 10
    ```

- **Change the Number of Days to Fetch Emails:**

    Specify the number of days to fetch emails from using the `--days` flag (default is 7 days):

    ```bash
    python3 MailScrub.py --days 14
    ```

## Script Components

1. **Authentication:**
    - The `authenticate_google()` function handles the OAuth2 authentication with the Gmail API.
    - The user will need to authenticate their Google account the first time the script is run, generating a `token.json` file for future use.

2. **Fetching Emails:**
    - The `fetch_emails()` function fetches emails that match the criteria (emails received within a given number of days, excluding those with the `MailScrubbed` or `stay-subscribed` labels).

3. **Finding Unsubscribe Links:**
    - The `find_unsubscribe_link()` function searches for unsubscribe links in the email body.

4. **Unsubscribing from Emails:**
    - The `unsubscribe_emails()` function uses Selenium to navigate to the unsubscribe links and logs the action.

5. **Managing Labels:**
    - The script uses the `MailScrubbed` label to mark emails that have been processed, and the `do-not-unsubscribe` label to exclude certain emails from unsubscription.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! Please fork the repository, create a new branch, and submit a pull request.

## Disclaimer

This tool is provided “as is,” without any warranties, express or implied. The authors are not liable for any damages or issues arising from its use. You are solely responsible for verifying unsubscribe actions and excluding important emails or domains. Use at your own risk.
