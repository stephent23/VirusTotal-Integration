import ConfigParser
import requests
import json

class VirusTotal(object):
    def __init__(self):
        # Define the configuration file
        config = ConfigParser.ConfigParser()
        config.read('conf.ini')
        
        # Get the API Key from the config file
        self.apikey = config.get('Remote_Configuration', 'API_Key')
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
            print(json.loads(result.text))



vt = VirusTotal()
vt.retrieve_domain_report('http://google.com')