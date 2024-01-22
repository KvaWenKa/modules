import requests
from datetime import datetime, timedelta

def parser_alienvault(ioc):
    
    if not ioc['type'] in ['ip','hash', 'domain']:
        return None
        
    ticket_IOC = {
        'value' : ioc,
        'vendor': 'AV'}

    urls = {'hash':'https://otx.alienvault.com/api/v1/indicators/file/',
            'ip':'https://otx.alienvault.com/api/v1/indicators/IPv4/',
            'domain':'https://otx.alienvault.com/api/v1/indicators/domain/'}
    try:
        response = requests.request(method='GET', url=urls[ioc['type']] + ioc['data'], verify=False)
        print(response.status_code)
        if response.status_code == 200:
            response = response.json()
            # СТРАНА
            if 'country_name' in response:
                ticket_IOC['country'] = response['country_name']
            # КАТЕГОРИИ
            # categories

            if 'validation' in response:
                ticket_IOC['categories'] = []
                for elem in response['validation']:
                    ticket_IOC['categories'].append(elem['name'])
            # РЕПУТАЦИЯ
            ticket_IOC['reputation'] = response['pulse_info']['count']
            # ТЕГИ
            tags = []
            now = datetime.now()
            colors_pulses = {'red' : 0, 'yellow' : 0, 'green' : 0}
            for pulse in response['pulse_info']['pulses']:
                if pulse['export_count'] > 48 and pulse['subscriber_count'] > 9:
                    date_create = datetime.strptime(pulse['created'].split('T')[0], "%Y-%m-%d").strftime("%Y-%m-%d")
                    if (now - datetime.strptime(date_create,"%Y-%m-%d") > timedelta(days=365)):
                        colors_pulses['green'] += 1
                    elif (now - datetime.strptime(date_create,"%Y-%m-%d") > timedelta(days=90)):
                        colors_pulses['yellow'] += 1
                        for tag in pulse['tags']:
                            if not tag.lower() in tags:
                                tags.append(tag.lower())
                    else:
                        colors_pulses['red'] += 1
                        for tag in pulse['tags']:
                            if not tag.lower() in tags:
                                tags.append(tag.lower())
            tags += response['pulse_info']['related']['alienvault']['malware_families']
            for tag in response['pulse_info']['related']['other']['malware_families']:
                if not tag in tags:
                    tags.append(tag)
            ticket_IOC["tags"] = tags
            # ВЕРДИКТ
            if colors_pulses['red'] != 0:
                ticket_IOC["verdict"] = 'red'
            elif colors_pulses['yellow'] != 0:
                ticket_IOC["verdict"] = 'yellow'
            else:
                ticket_IOC["verdict"] = 'green'
        return ticket_IOC
    except:
        print(f" {ticket_IOC['vendor']} ERROR")
        return None