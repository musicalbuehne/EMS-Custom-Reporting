# credentials.example.py
# Example credentials file for EMS Custom Reporting
# Copy this file to credentials.py and fill in your actual EMS credentials.

EMS_HOST = 'https://your-ems-server/'        # e.g., 'https://ems.example.com'
USERNAME = 'your-username'                   # Replace with your API username
PASSWORD = 'your-password'                   # Replace with your API password
SITE = 'default'                             # Only needs to be changed in MSSP environments
MAX_RETRIES = 3                              # Maximum number of retries for flawless API responses
REPORTS_FOLDER = '/path/to/reports/folder'   # Folder to save reports, gets created if it doesn't exist

# Instructions:
# 1. Copy this file to credentials.py in the same directory.
# 2. Edit credentials.py and enter your actual EMS server, username, and password.
# 3. Do NOT commit credentials.py to version control (it is already in .gitignore).
