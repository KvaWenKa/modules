import requests
from datetime import datetime, timedelta

def parser_criminalip(ioc):
    
    if not ioc['type'] in ['ip', 'domain']:
        return None
        
    headers = {
            'x-api-key': 'aGA06vl0lQ91aybIFUDsKuhaBV9hz3M8MH6fhg3utHTAlflEtHXGZT4jBOso'
        }
    
    ticket_IOC = {
        'value' : ioc,
        'vendor': 'CIP'}
    try:
        if ioc["type"] == "ip":
            querystring = {
                    'ip':ioc["data"]
                }
            url = 'https://api.criminalip.io/v1/ip/data'
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
            if response.status_code == 200:
                response = response.json()
                # ТЕГИ
                ticket_IOC["tags"] = []
                if "tags" in response:
                    for tag in response["tags"]:
                        if response["tags"][tag]:
                            ticket_IOC["tags"].append(tag)
                for tag in response["ip_category"]["data"]:
                        if not tag['type'] in ticket_IOC["tags"]:
                            ticket_IOC["tags"].append(tag['type'])
                # ВЕРДИКТ
                if response["score"]["inbound"] > 3 or response["score"]["outbound"] > 3:
                    ticket_IOC["verdict"] = 'red'
                elif response["score"]["inbound"] > 1 or response["score"]["outbound"] > 1:
                    ticket_IOC["verdict"] = 'yellow'
                else:
                    ticket_IOC["verdict"] = 'green'
                # РЕПУТАЦИЯ
                ticket_IOC["reputation"] = response["ids"]["count"]
                # СТРАНА
                if "data" in response["whois"]:
                    if "org_country_code" in response["whois"]["data"]:
                        ticket_IOC["country"] = response["whois"]["data"]["org_country_code"]
                # ВЛАДЕЛЕЦ
                    if "org_name" in response["whois"]["data"]:
                        ticket_IOC["owner"] = response["whois"]["data"]["org_name"]
                # ДОМЕНЫ
                ticket_IOC["domains_count"] = response["domain"]["count"]
        else:
            querystring = {
                'query':ioc["data"]
            }
            url_domain = 'https://api.criminalip.io/v1/domain/reports'
            url2_domain = 'https://api.criminalip.io/v1/domain/report/'
            response = requests.request(method='GET', url=url_domain, headers=headers, params=querystring, verify=False)
            if response.status_code == 200:
                response = response.json()
                if len(response["data"]["reports"]) > 0:
                    response = requests.request(method='GET', url=url2_domain+response["data"]["reports"][0]["scan_id"], headers=headers, verify=False)
                    if response.status_code == 200:
                        response = response.json()
                        # ВЕРДИКТ
                        ticket_IOC["verdict"] = ""
                        ticket_IOC["tags"] = []
                        if "summary" in response["data"]:
                            if "abuse_record" in response["data"]["summary"]:
                                if response["data"]["summary"]["abuse_record"]["critical"] > 0:
                                    ticket_IOC["verdict"] = 'red'
                                elif response["data"]["summary"]["abuse_record"]["dangerous"] > 0:
                                    ticket_IOC["verdict"] = 'yellow'
                                else:
                                    ticket_IOC["verdict"] = 'green'
                            # ТЕГИ
                            for elem in response["data"]["summary"]:
                                if response["data"]["summary"][elem] == True and type(response["data"]["summary"][elem]) != int:
                                    ticket_IOC["tags"].append(elem)
                        if "mapped_ip" in response["data"]:
                            ticket_IOC["country"] = []
                            ticket_IOC["ip"]  = []
                            for ip in response["data"]["mapped_ip"]:
                        # СТРАНА
                                if "country" in ip:
                                    ticket_IOC["country"].append(ip["country"])
                        # IP – АДРЕСА
                                if "ip" in ip:
                                    ticket_IOC["ip"].append(ip["ip"])
        return ticket_IOC
    except:
        print(f" {ticket_IOC['vendor']} ERROR")
        return None