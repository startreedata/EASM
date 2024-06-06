import datetime
import subprocess
import os
import io
import sys
import yaml
import requests
import json
import base64
from prettytable import PrettyTable
import logging

# Setting up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of IPs or domains to be scanned
TARGETS = []
# Determine the base path using the script's directory
base_path = os.path.dirname(os.path.realpath(__file__))
yaml_file_path = os.path.join(base_path, "EASM_tool", "domains.yml")

# Load IPs from YAML file
if not os.path.exists(yaml_file_path):
    logging.error(f"Error: domains.yml file not found at {yaml_file_path}.")
    exit(1)
else:
    logging.info(f"Loading targets from {yaml_file_path}")
    with open(yaml_file_path, 'r') as file:
        domains_data = yaml.safe_load(file)
        for ip in domains_data.values():
            if ip is not None and ip != "NA" and ip not in TARGETS:
                TARGETS.append(ip)

# Function to check and install Raccoon
def check_and_install_raccoon():
    if subprocess.run("which raccoon", shell=True, stdout=subprocess.DEVNULL).returncode != 0:
        logging.info("Raccoon not found, installing...")
        subprocess.run("pip install raccoon-scanner", shell=True, check=True)

# Function to run Raccoon and return its output
def run_raccoon(target):
    command = f"raccoon --full http://{target}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip(), True
    except subprocess.CalledProcessError as error:
        return error.output.strip(), False

# Function to parse and format Raccoon's output for the table
def parse_raccoon_output(output):
    issues = []
    if "vulnerability" in output:
        issues.append("Potential vulnerabilities found.")
    if "misconfiguration" in output:
        issues.append("Security misconfiguration detected.")
    return "\n".join(issues)

# Function to create JIRA issue
def create_jira_issue(target, jira_desc):
    jira_email = os.getenv('JIRA_EMAIL')
    jira_api_token = os.getenv('JIRA_API_COMA_TOKEN')
    base_url = 'https://startree.atlassian.net'
    api_url = f'{base_url}/rest/api/3/issue/'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + base64.b64encode(f'{jira_email}:{jira_api_token}'.encode()).decode()
    }
    issue_data = {
        'fields': {
            'project': {'key': 'SECOPS'},
            'summary': f'Scan of {target} - SECOPS - created by GitHub Actions',
            'description': f'{jira_desc}',
            'issuetype': {'name': 'Task'}
        }
    }
    response = requests.post(api_url, headers=headers, data=json.dumps(issue_data))
    if response.status_code in [200, 201]:
        logging.info(f'Issue created successfully! Issue Key: {response.json()["key"]}')
    else:
        logging.error(f'Failed to create issue. Status code: {response.status_code}')
        logging.error(response.text)

def main(targets):
    check_and_install_raccoon()
    
    for target in targets:
        logging.info(f"Starting Raccoon scan for {target}")
        raccoon_output, success = run_raccoon(target)
        
        if not success:
            logging.error("Raccoon scan failed for", target)
            continue
        
        # Redirect stdout to a string buffer
        stdout_backup = sys.stdout
        sys.stdout = io.StringIO()
        
        # Create a PrettyTable object
        table = PrettyTable()
        table.field_names = ["Check", "Result"]
        parsed_results = parse_raccoon_output(raccoon_output)
        table.add_row(["Raccoon Scan", parsed_results])
        
        # Print the table
        print(table)
        
        # Get all the printed statements from console output
        target_output = sys.stdout.getvalue()
        # Restore stdout
        sys.stdout = stdout_backup
        
        # Optional: Replace or implement functions to handle output
        # Example: create_git_file_store(target, target_output)
        # Example: get_delta(target, target_output)

if __name__ == "__main__":
    main(TARGETS)
