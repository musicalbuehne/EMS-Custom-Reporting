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
from collections import defaultdict

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
    url = f"{ems_host}/api/v1/endpoints/index?count=1000" # If there are more than 1000 clients, you may need to implement pagination
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

    # Sort client_details_list by ['groups'][0]['group_path']
    # client_details_list.sort(key=lambda x: x['groups'][0]['group_path'] if x['groups'] else '')

    pdf = PDFWithPageNumbers(orientation='L')
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    # Centered title
    pdf.set_font("Arial", 'B', 16)
    page_width = pdf.w - 2 * pdf.l_margin
    pdf.cell(page_width, 10, txt="FCT Version by Group Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(page_width, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} from {EMS_HOST}", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    # Table header
    pdf.set_left_margin(10)
    pdf.set_right_margin(10)
    pdf.set_auto_page_break(auto=True, margin=15)
    col_widths = [60, 50, 90, 70]  # Adjusted column widths as needed
    
    # Add client details to the PDF
    # Group clients by their first group_path
    grouped_clients = defaultdict(list)
    for client in client_details_list:
        group_path = client['groups'][0]['group_path'] if client['groups'] else 'No Group'
        grouped_clients[group_path].append(client)

    for group, clients in grouped_clients.items():
        # Add group title
        pdf.set_font("Arial", 'B', 12)
        # If group name is too long, wrap to new line(s)
        group_text = str(group)
        max_width = sum(col_widths)
        if pdf.get_string_width(group_text) > max_width:
            pdf.multi_cell(max_width, 10, group_text, 1, align='L')
        else:
            pdf.cell(max_width, 10, group_text, 1, ln=True, align='L')
        pdf.set_font("Arial", 'B', size=10)
        # Table header for each group
        pdf.cell(col_widths[0], 10, "Host", 1)
        pdf.cell(col_widths[1], 10, "FCT Version", 1)
        #pdf.cell(col_widths[2], 10, "Group", 1)
        pdf.cell(col_widths[3], 10, "Last Seen", 1)
        pdf.set_font("Arial",  size=10)
        pdf.ln()
        for client in clients:
            pdf.cell(col_widths[0], 10, f"{client['host']} ({client['device_id']})", 1)
            pdf.cell(col_widths[1], 10, str(client['fct_version']), 1)
            #pdf.cell(col_widths[2], 10, str(group), 1)
            pdf.cell(col_widths[3], 10, str(client['last_seen']), 1)
            pdf.ln()
        pdf.ln(5)
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
    filename = f"fct_version_by_group_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
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
                            fct_version = details['data'].get('fct_version', 'N/A')
                            groups = details['data'].get('groups', [])
                            last_seen = details['data'].get('last_seen', 'N/A')
                            client_info = {
                                "device_id": device_id,
                                "host": host,
                                "fct_version": fct_version,
                                "groups": groups,
                                "last_seen": datetime.fromtimestamp(last_seen).strftime('%Y-%m-%d %H:%M:%S') if last_seen else 'N/A'
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
        print(f"Host: {client['host']} ({client['device_id']}), FCT Version: {client['fct_version']}, Groups: {client['groups']}, Last Seen: {client['last_seen']}")
    # Create a PDF report with the client details
    generate_pdf(client_details_list)

# Ensure the script runs only when executed directly
if __name__ == "__main__":
    main()