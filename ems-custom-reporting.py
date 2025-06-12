## Disclaimer
# This script is provided as-is and is not officially supported. Use at your own risk.
# It was hacked together in a few hours and is in no way tested or guaranteed to work with all versions of Fortinet EMS. 
# Alexander Uhlmann, 2025

import requests
import urllib3
from config import EMS_HOST, USERNAME, PASSWORD, SITE, MAX_RETRIES, REPORTS_FOLDER
from fpdf import FPDF
from datetime import datetime
import os

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_URL = f"{EMS_HOST}/api/v1/auth/signin"

headers = {
    'Content-Type': 'application/json',
    'Ems-Call-Type': '2',
}

payload = {
    'name': USERNAME,
    'password': PASSWORD,
    'site': SITE
}

client_details_list = []
error_list = []

# Function to get all clients from EMS
def get_all_clients(session, ems_host, csrf_token):
    url = f"{ems_host}/api/v1/endpoints/index"
    headers = {
        'Content-Type': 'application/json',
        'Ems-Call-Type': '2',
        'X-CSRFToken': csrf_token,
        'Referer': ems_host.rstrip('/')
    }
    response = session.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        error_string = f'Failed to get clients: {response.status_code} {response.text}'
        error_list.append(error_string)
        print(error_string)
        return None

# Function to get details for a specific client
def get_client_details(session, ems_host, csrf_token, client_id):
    url = f"{ems_host}/api/v1/endpoints/device/{client_id}/details"
    headers = {
        'Content-Type': 'application/json',
        'Ems-Call-Type': '2',
        'X-CSRFToken': csrf_token,
        'Referer': ems_host.rstrip('/')
    }
    response = session.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        error_string = f'Failed to get details for client {client_id}: {response.status_code} {response.text}'
        error_list.append(error_string)
        print(error_string)
        return None

# Function to log out from EMS
def logout(session, ems_host, csrf_token):
    signout_url = f"{ems_host}/api/v1/auth/signout"
    signout_headers = {
        'Content-Type': 'application/json',
        'Ems-Call-Type': '2',
        'X-CSRFToken': csrf_token,
        'Referer': ems_host.rstrip('/')
    }
    signout_response = session.post(signout_url, headers=signout_headers, verify=False)
    if signout_response.status_code == 200:
        print('Logged out successfully.')
    else:
        print(f'Logout failed: {signout_response.status_code} {signout_response.text}')

# Function to generate a PDF report with client details
def generate_pdf(client_details_list):
    class PDFWithPageNumbers(FPDF):
        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            page_num = f'Page {self.page_no()} of {{nb}}'
            self.cell(0, 10, page_num, 0, 0, 'R')

    pdf = PDFWithPageNumbers(orientation='L')
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    # Centered title
    pdf.set_font("Arial", 'B', 16)
    page_width = pdf.w - 2 * pdf.l_margin
    pdf.cell(page_width, 10, txt="EMS Client Details Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(page_width, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} from {EMS_HOST}", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    # Table header
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    pdf.set_auto_page_break(auto=True, margin=15)
    col_widths = [80, 30, 50, 50, 60]  # Adjusted column widths as needed
    # Header row
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(col_widths[0], 10, "Host", 1)
    pdf.cell(col_widths[1], 10, "AV Installed", 1)
    pdf.cell(col_widths[2], 10, "AV Sig Version", 1)
    pdf.cell(col_widths[3], 10, "AV Sig Up to Date", 1)
    pdf.cell(col_widths[4], 10, "Last Seen", 1)
    pdf.ln()
    pdf.set_font("Arial", size=10)
    # Add client details to the PDF
    for client in client_details_list:
        pdf.cell(col_widths[0], 10, f"{client['host']} ({client['device_id']})", 1)
        pdf.cell(col_widths[1], 10, str(client['av_installed']), 1)
        pdf.cell(col_widths[2], 10, str(client['av_sig_version']), 1)
        pdf.cell(col_widths[3], 10, str(client['av_sig_status']), 1)
        pdf.cell(col_widths[4], 10, str(client['last_seen']), 1)
        pdf.ln()
    # Add a second page for errors if there are any
    pdf.add_page()
    if error_list:
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Errors", ln=True)
        pdf.ln(10)
        pdf.set_font("Arial", size=10)
        for error in error_list:
            pdf.multi_cell(0, 10, error)
    else:
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="No errors encountered.", ln=True)
    # Save the PDF to a file
    filename = f"client_details_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    if not os.path.exists(REPORTS_FOLDER):
        os.makedirs(REPORTS_FOLDER)
    filepath = os.path.join(REPORTS_FOLDER, filename)
    pdf.output(filepath)
    print(f"PDF report generated: {filename}")

# Function to fetch and process client details
def fetch_and_process_clients():
    with requests.Session() as session:
        response = session.post(LOGIN_URL, json=payload, headers=headers, verify=False)  # Set verify=True for valid SSL
        if response.status_code == 200:
            print('Login successful.')
            csrf_token = session.cookies.get('csrftoken')
            # print(f'CSRF Token: {csrf_token}')
            # Get all clients and print result
            clients = get_all_clients(session, EMS_HOST, csrf_token)
            #print('Clients:', clients)
            if clients and 'data' in clients:
                endpoints = clients['data']['endpoints']
                total_clients = len(endpoints)
                print(f"Found {total_clients} clients. Fetching details ...")
                for idx, client_id in enumerate(endpoints, 1):
                    if client_id is not None:
                        device_id = client_id.get('device_id')
                        print(f"Processing client {idx}/{total_clients} (Device ID: {device_id}) ...")
                        details = get_client_details(session, EMS_HOST, csrf_token, device_id)
                        #print(f'Details for client {client_id}:', details['data'])
                        if details and 'data' in details:
                            device_id = details['data'].get('device_id', 'N/A')
                            host = details['data'].get('host', 'N/A')
                            av_installed = details['data'].get('av_installed', 'N/A')
                            last_seen = datetime.fromtimestamp(details['data']['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if details['data'].get('last_seen') else 'N/A'
                            if not av_installed: # If AV is not installed, set default values
                                av_installed = 'False'
                                av_sig_status = 'N/A'
                                av_sig_version = 'N/A'
                            else: # If AV is installed, get the signature version and status
                                av_sig_status = details['data'].get('client_av_sig_version_up_to_date', 'N/A')
                                av_sig_version = details['data'].get('av_sig_version', 'N/A')
                            client_info = {
                                "device_id": device_id,
                                "host": host,
                                "av_installed": av_installed,
                                "av_sig_version": av_sig_version,
                                "av_sig_status": av_sig_status,
                                "last_seen": last_seen
                            }
                            client_details_list.append(client_info)
                print("Finished fetching client details.")
            # Call the logout function at the end
            logout(session, EMS_HOST, csrf_token)
        else:
            error_string = f'Login failed: {response.status_code} {response.text}'
            error_list.append(error_string)
            print(error_string)

# Main function to handle retries and generate the report
def main():
    attempt = 0

    while attempt < MAX_RETRIES:
        # Clear previous results and errors before each attempt
        client_details_list.clear()
        error_list.clear()
        fetch_and_process_clients()
        if not error_list:
            break
        print(f"Attempt {attempt + 1} / {MAX_RETRIES} failed with errors. Retrying ...")
        attempt += 1

    # Print the client details
    for client in client_details_list:
        print(f"Host: {client['host']} ({client['device_id']}), AV Installed: {client['av_installed']}, AV Signature Version: {client['av_sig_version']}, AV Signature Up to Date: {client['av_sig_status']}, Last Seen: {client['last_seen']}")
    # Create a PDF report with the client details
    generate_pdf(client_details_list)

# Ensure the script runs only when executed directly
if __name__ == "__main__":
    main()