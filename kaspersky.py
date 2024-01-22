import requests
from datetime import datetime, timedelta

def parser_kasperskyTI(ioc):
    if not ioc['type'] in ['ip','hash', 'domain']:
        return None
    
    ticket_IOC = {
        'value' : ioc,
        'vendor': 'KIT'}
    headers = {
            'x-api-key': 'o6pFbOzuSIWgeTt+hx01MQ=='
    }

    querystring = {
            'request':ioc["data"]
    }
    url = 'https://opentip.kaspersky.com/api/v1/search/'
    # url_ip_adress = 'https://opentip.kaspersky.com/api/v1/search/ip'
    # url_domain = 'https://opentip.kaspersky.com/api/v1/search/domain'
    # url_hash = 'https://opentip.kaspersky.com/api/v1/search/hash'
    try:
        response = requests.request(method='GET', url=url + ioc["type"], headers=headers, params=querystring, verify=False)
        if response.status_code == 200:
            response = response.json()
            # ВЕРДИКТ
            if response["Zone"].lower() in ['grey','orange']:
                ticket_IOC["verdict"] = 'yellow'
            else:
                ticket_IOC["verdict"] = response["Zone"].lower()
            if "IpGeneralInfo" in response:
                # ТЕГИ
                if "Categories" in response["IpGeneralInfo"]:
                    ticket_IOC["tags"] = response["IpGeneralInfo"]["Categories"]
                # РЕПУТАЦИЯ
                if "HitsCount" in response["IpGeneralInfo"]:
                    ticket_IOC["reputation"] = response["IpGeneralInfo"]["HitsCount"]
                # СТРАНА
                if "CountryCode" in response["IpGeneralInfo"]:
                    ticket_IOC["country"] = response["IpGeneralInfo"]["CountryCode"]
            if "IpWhoIs" in response and "Net" in response["IpWhoIs"]:
                # ДАТА СОЗДАНИЯ
                if "Created" in response["IpWhoIs"]["Net"]:
                    ticket_IOC["created"] = response["IpWhoIs"]["Net"]["Created"].split('T')[0]
                # ДАТА ОБНОВЛЕНИЯ
                if "Changed" in response["IpWhoIs"]["Net"]:
                    ticket_IOC["changed"] = response["IpWhoIs"]["Net"]["Changed"].split('T')[0]
                # ВЛАДЕЛЕЦ
                if "Name" in response["IpWhoIs"]["Net"]:
                    ticket_IOC["owner"] = response["IpWhoIs"]["Net"]["Name"]
            # ДОМЕН
            if "DomainGeneralInfo" in response:
                # РЕПУТАЦИЯ
                if "HitsCount" in response["DomainGeneralInfo"]:
                    ticket_IOC["reputation"] = response["DomainGeneralInfo"]["HitsCount"]
                # КАТЕГОРИИ
                if "Categories" in response["DomainGeneralInfo"]:
                    ticket_IOC["categories"] = response["DomainGeneralInfo"]["Categories"]
                # Кол-во IP
                if "Ipv4Count" in response["DomainGeneralInfo"]:
                    ticket_IOC["ip_count"] = response["DomainGeneralInfo"]["Ipv4Count"]
            if "DomainWhoIsInfo" in response:
                # ВЛАДЕЛЕЦ
                if "RegistrationOrganization" in response["DomainWhoIsInfo"]:
                    ticket_IOC["owner"] = response["DomainWhoIsInfo"]["RegistrationOrganization"]
                # ДАТА ОБНОВЛЕНИЯ
                if "Updated" in response["DomainWhoIsInfo"]:
                    ticket_IOC["changed"] = response["DomainWhoIsInfo"]["Updated"].split('T')[0]
                # ДАТА СОЗДАНИЯ
                if "Created" in response["DomainWhoIsInfo"]:
                    ticket_IOC["created"] = response["DomainWhoIsInfo"]["Created"].split('T')[0]
                
                if "Contacts" in response["DomainWhoIsInfo"] and len(response["DomainWhoIsInfo"]) > 0:
                    # СТРАНА
                    if "CountryCode" in response["DomainWhoIsInfo"]["Contacts"][0]:
                        ticket_IOC["country"] = response["DomainWhoIsInfo"]["Contacts"][0]["CountryCode"]
                    # Организация
                    if "Organization" in response["DomainWhoIsInfo"]["Contacts"][0]:
                        ticket_IOC["organization"] = response["DomainWhoIsInfo"]["Contacts"][0]["Organization"]
            # ФАЙЛ
            if "FileGeneralInfo" in response:
                # ТИП ФАЙЛА
                if "Type" in response["FileGeneralInfo"]:
                    ticket_IOC["type_file"] = response["FileGeneralInfo"]["Type"]
                # РАЗМЕР ФАЙЛА
                if "Size" in response["FileGeneralInfo"]:
                    ticket_IOC["size_file"] = response["FileGeneralInfo"]["Size"]
                # ПОДПИСЬ
                if "Signer" in response["FileGeneralInfo"]:
                    ticket_IOC["signer"] = response["FileGeneralInfo"]["Signer"]
                # Дата проверки
                if "LastSeen" in response["FileGeneralInfo"]:
                    ticket_IOC["lastseen_file"] = response["FileGeneralInfo"]["LastSeen"].split('T')[0]
            if "DetectionsInfo" in response:
                ticket_IOC["tags"] = []
                for elem in response["DetectionsInfo"]:
                    ticket_IOC["tags"].append(elem["DetectionName"])
            
            return ticket_IOC
    except:
        print(f" {ticket_IOC['vendor']} ERROR")
        return None