import argparse
import configparser
import requests
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
        result = requests.post(url, data = params)
        
        if result.status_code == self.HTTP_OK:
            print('Domain scan requested.')

    def retrieve_domain_report(self, domain):
        url = self.URL_BASE + 'url/report'

        params = {'apikey': self.apikey, 'resource': domain}
        result = requests.post(url, data=params)

        if result.status_code == self.HTTP_OK:
            result = json.loads(result.text)
            return result


def control_output(json_data, csv_required, dump_required):
    print(csv_required)
    print(dump_required)
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
    selected_detected = json_data['scans'][vt.network_detection_engine_preference]['detected']
    selected_result = json_data['scans'][vt.network_detection_engine_preference]['result']

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
    selected_detected = json_data['scans'][vt.network_detection_engine_preference]['detected']
    selected_result = json_data['scans'][vt.network_detection_engine_preference]['result']

    # build csv row
    row = [url, scandate, positives, total_engines, selected_engine, selected_detected, selected_result]

    # CSV to write to 
    filepath = config.get('Output_Files', 'Output_CSV')
    with open(filepath, mode='a') as output_file:
        csv_writer = csv.writer(output_file)
        csv_writer.writerow(row)  


# Get command line arguments
parser = argparse.ArgumentParser(prog="Virus Total API")

parser.add_argument("--csv", help="Sends some output to a CSV file.", action="store_true")
parser.add_argument("--dump", help="Dumps the full VirusTotal output to a json file.", action="store_true")
# Either pass a single url on the command line or provide a path to a CSV.
inputformat = parser.add_mutually_exclusive_group(required=True)
inputformat.add_argument("--url", help="The URL that you would like to receive the report for.")
inputformat.add_argument("--list", help="This can be used to point the script at a file which contains a list of URLs that need to be searched.")

args = parser.parse_args()


# Define the configuration file
config = configparser.ConfigParser()
config.read('conf.ini')

# Establish VT 
vt = VirusTotal()
if(args.url):
    report = vt.retrieve_domain_report(args.url)
    print_to_terminal(report)
elif (args.list):
    with open(args.list, mode='a') as input_file:
        list_of_urls = input_file.readlines()
        for url in list_of_urls:
            report = vt.retrieve_domain_report(url)
            print(str(args.csv))
            control_output(report, args.csv, args.dump)
