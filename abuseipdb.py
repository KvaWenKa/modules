import requests

AB_API_KEY = 'c4971c216cd2a89be69e8c2d47b18a3c308c27d5d94e51fba6d7cc3c0b448a8eeca295e9536a961e'

def parser_abuseip(ioc):

    if not ioc['type'] in ['ip']:
        return None

    ticket_IOC = {
        'value' : ioc,
        'vendor': 'AIPDB'}
    
    AB_URL_CHECK = 'https://api.abuseipdb.com/api/v2/check'
    AB_URL_REPORTS = 'https://api.abuseipdb.com/api/v2/reports'
    days = '120'
    categories = ['DNS Compromise', 'DNS Poisoning', 'Fraud Orders', 'DDoS Attack ',
                    'FTP Brute-Force', 'Ping of Death ', 'Phishing ', 'Fraud VoIP',
                    'Open Proxy', 'Web Spam', 'Email Spam', 'Blog Spam', 'VPN IP', 'Port Scan',
                    'Hacking', 'SQL Injection', 'Spoofing', 'Brute-Force', 'Bad Web Bot',
                    'Exploited Host', 'Web App Attack', 'SSH', 'IoT Targeted']

    querystring = {
            'ipAddress': ioc['data'],
            'maxAgeInDays': days
        }

    headers = {
            'Accept': 'application/json',
            'Key': AB_API_KEY
        }
    try:
        response = requests.request(method='GET', url=AB_URL_CHECK, headers=headers, params=querystring, verify=False)
        if response.status_code == 200:
            response = response.json()
            # ВЕРДИКТ
            if response['data']['totalReports'] > 1 and response["data"]["abuseConfidenceScore"] > 0:
                ticket_IOC["verdict"] = 'red'
            elif response['data']['totalReports'] > 1 and response["data"]["abuseConfidenceScore"] == 0:
                ticket_IOC["verdict"] = 'yellow'
            else:
                ticket_IOC["verdict"] = 'green'
            # РЕПУТАЦИЯ
            if "totalReports" in response["data"]:
                ticket_IOC["reputation"] = response["data"]["totalReports"]
                # ТЕГИ
                ticket_IOC["tags"] = []
                for elem in response["data"]:
                            if response["data"][elem] == True and type(response["data"][elem]) != int:
                                ticket_IOC["tags"].append(elem)
                if response["data"]["totalReports"] > 0:
                    response_reports = requests.request(method='GET', url=AB_URL_REPORTS, headers=headers,
                                            params=querystring, verify=False)
                    if response_reports.status_code == 200:
                        reports = response_reports.json()
                        for r in reports['data']['results']:
                            for categor in r['categories']:
                                if not categories[categor-1] in ticket_IOC["tags"]:
                                    ticket_IOC["tags"].append(categories[categor-1])
            # СТРАНА
            if "countryCode" in response["data"]:
                ticket_IOC["country"] = response["data"]["countryCode"]
            # ВЛАДЕЛЕЦ
            if "isp" in response["data"]:
                ticket_IOC["owner"] = response["data"]["isp"]
            # ДОМЕНЫ
            ticket_IOC["domains"] = []
            ticket_IOC["domains_count"] = 0
            if "hostnames" in response["data"] and len(response["data"]["hostnames"]) > 0:
                ticket_IOC["domains_count"] += len(response["data"]["hostnames"])
                ticket_IOC["domains"] += (response["data"]["hostnames"])
            if "domain" in response["data"]:
                ticket_IOC["domains_count"] += 1
                ticket_IOC["domains"].append(response["data"]["domain"]) 
        return ticket_IOC
    except:
        print(f" {ticket_IOC['vendor']} ERROR")
        return None