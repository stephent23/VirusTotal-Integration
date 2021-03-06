import argparse
import configparser
import requests
from datetime import datetime
import time
import json
import csv


class VirusTotal(object):
    def __init__(self):
        # Get the API Key from the config file
        self.apikey = config.get('Remote_Configuration', 'API_Key')

        # Get the preferencial detection engines
        self.files_detection_engine_preference = config.get('User_Preferences', 'Files_Detection_Engine_Preference')
        self.network_detection_engine_preference = config.get('User_Preferences', 'Network_Detection_Engine_Preference')

        self.URL_BASE = "https://www.virustotal.com/vtapi/v2/"
        self.HTTP_OK = 200

        # Is it a public API Key
        self.is_public_apikey = True


    def scan_domain(self, domain):
        url = self.URL_BASE + 'url/scan'

        params = {'apikey': self.apikey, 'url': domain}
        result = requests.post(url, data=params, proxies=proxies)

        if result.status_code == self.HTTP_OK:
            return True
        else:
            return False

    def retrieve_domain_report(self, domain):
        url = self.URL_BASE + 'url/report'

        params = {'apikey': self.apikey, 'resource': domain}
        result = requests.post(url, data=params, proxies=proxies)

        if result.status_code == self.HTTP_OK:
            result = json.loads(result.text)
            if self.check_report_available(result):
                return result
            else:
                return False

    def scan_and_retrieve_domain_report(self, domain):
        count = 1
        self.scan_domain(domain)
        print("Scanning...")
        time.sleep(15)
        # Retrieve report
        report = self.retrieve_domain_report(domain)

        # If scan time of report is not today, then sleep and retrieve report again
        while report==False or datetime.strptime(report['scan_date'], "%Y-%m-%d %H:%M:%S").date() < datetime.today().date() or report==None:
            if count > 5:
                return False
            else:
                print("Report not yet available. Waiting and trying again... (Try " + str(count) + "/5)")
                count += 1
                time.sleep(15)
                report = self.retrieve_domain_report(domain)
        return report

    def check_report_available(self, json_data):
        if(json_data['response_code'] == 0):
            return False
        else:
            return True


def set_proxy_config():
    proxy_config = {}
    proxies = None
    # Check if we should use a proxy
    if config.get('Proxy_Configuration', 'Use_Proxy') == 'True':
        # Get the proxy config
        proxy_config['address'] = config.get('Proxy_Configuration', 'Address')
        proxy_config['port'] = config.get('Proxy_Configuration', 'Port')
        proxy_config['user'] = config.get('Proxy_Configuration', 'Username')
        proxy_config['password'] = config.get('Proxy_Configuration', 'Password')
        proxies = {'https': 'http://' + proxy_config['user'] + ':' + proxy_config['password'] + '@' + proxy_config['address'] + ':' + proxy_config['port']}
    else:
        proxies = None

    return proxies

def get_urls_from_file():
    """ Returns a list of URLs that are read in from a file. """
    with open(args.list, mode='r') as input_file:
        return input_file.readlines()

def control_output(json_data, csv_required, dump_required):
    if(csv_required):
        write_to_csv(json_data)

    if(dump_required):
        dump_to_jsonfile(json_data)

    if(not(csv_required) and not(dump_required)):
        print_to_terminal(json_data)

# This should be refactored
def print_to_terminal(json_data):
    # Get the useful fields
    url = json_data['url']
    scandate = json_data['scan_date']
    positives = json_data['positives']
    total_engines = json_data['total']
    selected_engine = vt.network_detection_engine_preference

    # The selected detection engine will not always be available, catching that error.
    selected_detected = None
    try:
        selected_detected = json_data['scans'][vt.network_detection_engine_preference]['detected']
    except KeyError:
        selected_detected = str(vt.network_detection_engine_preference) + ": N/A"

    selected_result = None
    try: 
        selected_result = json_data['scans'][vt.network_detection_engine_preference]['result']
    except KeyError:
        selected_result = str(vt.network_detection_engine_preference) + ": N/A"

    print("")
    print("URL: " + url)
    print("Scan Date: " + scandate)
    print("Detection Rate: " + str(positives) + "/" + str(total_engines))
    print(selected_engine + ": ")
    print("     Detected: " + str(selected_detected))
    print("     Result: " + str(selected_result))
    print("")

def dump_to_jsonfile(json_data):
    filepath = config.get('Output_Files', 'Output_JSON')
    with open(filepath, mode='a') as output_file:
        json.dump(json_data, output_file, indent=4, sort_keys=True)

def write_to_csv(json_data):
    # Get the useful fields
    url = json_data['url']
    scandate = json_data['scan_date']
    positives = json_data['positives']
    total_engines = json_data['total']
    selected_engine = vt.network_detection_engine_preference

    # The selected detection engine will not always be available, catching that error.
    selected_detected = None
    try:
        selected_detected = json_data['scans'][vt.network_detection_engine_preference]['detected']
    except KeyError:
        selected_detected = str(vt.network_detection_engine_preference) + ": N/A"

    selected_result = None
    try: 
        selected_result = json_data['scans'][vt.network_detection_engine_preference]['result']
    except KeyError:
        selected_result = str(vt.network_detection_engine_preference) + ": N/A"

    # build csv row
    row = [url, scandate, positives, total_engines, selected_engine, selected_detected, selected_result]

    # CSV to write to
    filepath = config.get('User_Preferences', 'Output_CSV')
    with open(filepath, mode='a') as output_file:
        csv_writer = csv.writer(output_file)
        csv_writer.writerow(row)


# Get command line arguments
parser = argparse.ArgumentParser(prog="Virus Total API")

# Either pass a single url on the command line or provide a path to a CSV.
inputformat = parser.add_mutually_exclusive_group(required=True)
inputformat.add_argument("--url", help="The URL that you would like to receive the report for. Using this parameter, will print the results to the command line.")
inputformat.add_argument("--list", help="This can be used to point the script at a file which contains a list of URLs that need to be searched.")

parser.add_argument("--csv", help="Sends some output to a CSV file.", action='store_true')
parser.add_argument("--dump", help="Dumps the full VirusTotal output to a json file.", action='store_true')
parser.add_argument("--scan", help="Defines whether the domains should be scanned , otherwise the latest report will be retrieved.", action='store_true')

args = parser.parse_args()

# Define the configuration file
config = configparser.ConfigParser()
config.read('conf.ini')

# Check and set proxy config
proxies = set_proxy_config()

# Establish VT
vt = VirusTotal()

### URL GIVEN ON COMMAND LINE
if(args.url):
    # Scan requested
    if(args.scan):
        report = vt.scan_and_retrieve_domain_report(args.url)
        if report == False:
            print("Report unavailable at this time. Try again later.")
        else:
            print_to_terminal(report)
    else:
        report = vt.retrieve_domain_report(args.url)
        if report == False:
            print("Report unavailable at this time. Try again using the --scan parameter.")
        else: 
            print_to_terminal(report)

### LIST OF URLs GIVEN IN FILE
elif (args.list):
    ## SETUP
    list_of_urls = get_urls_from_file()
    # List to hold the domains that have been scanned as no report existed
    urls_pending_report = []

    for url in list_of_urls:
        report = vt.retrieve_domain_report(url)
        time.sleep(15)
        if report != False:
            control_output(report, args.csv, args.dump)
        else:
            vt.scan_domain(url)
            urls_pending_report.append(url)
            time.sleep(15)

    # Once all of the domains have been submitted, go back through the pending domains
    for url in urls_pending_report:
        report = vt.retrieve_domain_report(url)
        time.sleep(15)
        if report != False:
            control_output(report, args.csv, args.dump)
        else:
            print("Unable to generate report for: " + url)
