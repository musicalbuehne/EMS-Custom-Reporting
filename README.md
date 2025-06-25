# EMS Custom Reporting - API Demonstration Script
This script demonstrates how to interact with a Fortinet EMS server using its API to generate a custom report of endpoint details.

## Features
- Authenticates securely with EMS using API credentials
- Fetches all endpoint details
- Collects antivirus installation and signature status
- Generates a wellish-formatted PDF report
- Handles errors and retries automatically

## Requirements
- Python 3.7+
- Install dependencies:
  ```sh
  pip3 install requests fpdf
  ```

## Setup
1. **Clone the repository**
2. **Create your credentials file:**
   - Copy `config.example.py` to `config.py`:
     ```sh
     cp config.example.py config.py
     ```
   - Edit `config.py` and fill in your EMS server URL, username, and password.
3. **(Optional) Adjust retry settings** in `config.py` if needed.

## Usage
Run the script from your terminal:

```sh
python3 ems-custom-reporting.py
```

- The script will log in, fetch all client details, and generate a PDF report (e.g., `client_details_report_YYYYMMDD_HHMMSS.pdf`).
- Errors (if any) are included in a separate page in the PDF.

## Output Example
- Console output will show progress and summary.
- PDF report includes columns:
  - Host (and Device ID)
  - AV Installed
  - AV Signature Version
  - AV Signature Up to Date
  - Last Seen

## Possible Values to be Displayed
See `possible-client-details.txt` for a detailed list of all possible endpoint details that can be fetched and displayed in the report.
You can modify the script to include additional fields as needed. To get a preview of the available fields, GET the client details, e.g. via your browser:
```
https://<your-ems-server>/api/v1/endpoints/device/<ID>/details
```

## More Examples
Over time more examples might get added, such as fct-version-by-group.py to showcase different reporting options.

## Security
- **Never commit `config.py` to version control!**
- The `.gitignore` is configured to exclude sensitive files and common environment artifacts.

## License
MIT License

## Disclaimer
This script is provided as-is and is not officially supported. Use at your own risk.
It was hacked together in a few hours and is in no way tested or guaranteed to work with all versions of Fortinet EMS. 
