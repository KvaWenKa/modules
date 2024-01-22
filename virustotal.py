import requests
from datetime import datetime, timedelta

def parser_virus_total(ioc):
    
    url = f'https://www.virustotal.com/api/v3/search?query={ioc["data"]}'
    headers = {
            "accept": "application/json",
            "x-apikey": "e9fc286b889ecdc50585afbd9ef255ce9be7a8f1cdfe20a31e999b9d6c56adc8"
    }
    if not ioc['type'] in ['ip','hash', 'domain']:
        return None
    #Карточка ИК
    ticket_IOC = {
        'value' : ioc,
        'vendor': 'VT'}

    try:
        response = requests.get(url, headers=headers).json()
        fields = ["last_analysis_date", "tags", "last_analysis_stats", "reputation", "country", "categories"]
        if response["data"] != []:
            for field in fields:
                if field in response["data"][0]["attributes"]:
                    ticket_IOC[field] = response["data"][0]["attributes"][field]
            if "last_analysis_date" in ticket_IOC:
                ticket_IOC["last_analysis_date"] = str(datetime.fromtimestamp(ticket_IOC["last_analysis_date"]))
            if "categories" in response["data"][0]["attributes"]:
                ticket_IOC["categories"] = []
                for categor in response["data"][0]["attributes"]["categories"]:
                    ticket_IOC["categories"].append(response["data"][0]["attributes"]["categories"][categor])
            # ВЕРДИКТ
            if response["data"][0]["attributes"]["last_analysis_stats"]["malicious"] > 3:
                ticket_IOC["verdict"] = 'red'
            elif response["data"][0]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                ticket_IOC["verdict"] = 'yellow'
            else:
                ticket_IOC["verdict"] = 'green'
            # ДАТА СОЗДАНИЯ СЕТИ
            # ДАТА ИЗМЕНЕНИЯ СЕТИ
            # ВЛАДЕЛЕЦ
            if "as_owner" in response["data"][0]["attributes"]:
                ticket_IOC["owner"] = response["data"][0]["attributes"]["as_owner"]
            # ДОМЕН IP
            if "last_dns_records" in response["data"][0]["attributes"]:
                ticket_IOC["ip"] = []
                for records in response["data"][0]["attributes"]["last_dns_records"]:
                    if records['type'] == 'A':
                        ticket_IOC["ip"].append(records['value'])
            # ДОМЕН СТРАНА
            if "last_https_certificate" in response["data"][0]["attributes"] and "C" in response["data"][0]["attributes"]["last_https_certificate"]["issuer"]:
                ticket_IOC["country"] = response["data"][0]["attributes"]["last_https_certificate"]["issuer"]["C"]
            # ТИП ФАЙЛА
            if "type_tags" in response["data"][0]["attributes"]:
                ticket_IOC["type_file"] = response["data"][0]["attributes"]["type_tags"]
            # ИМЕНА ФАЙЛА
            if "names" in response["data"][0]["attributes"]:
                ticket_IOC["names_file"] = response["data"][0]["attributes"]["names"]
            # РАЗМЕР ФАЙЛА
            if "size" in response["data"][0]["attributes"]:
                ticket_IOC["size_file"] = response["data"][0]["attributes"]["size"]
            # ПЕСОЧНИЦЫ
            if "sandbox_verdicts" in response["data"][0]["attributes"]:
                ticket_IOC["sandbox_verdicts"] = []
                for sandbox in response["data"][0]["attributes"]["sandbox_verdicts"]:
                    ticket_IOC["sandbox_verdicts"].append(response["data"][0]["attributes"]["sandbox_verdicts"][sandbox]["malware_classification"])
        return ticket_IOC
    except:
        print(f" {ticket_IOC['vendor']} ERROR")
        return None