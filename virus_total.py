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


# Define the configuration file
config = configparser.ConfigParser()
config.read('conf.ini')

# Establish VT 
vt = VirusTotal()
report = vt.retrieve_domain_report('http://google.com')
dump_to_jsonfile(report)
write_to_csv(report)