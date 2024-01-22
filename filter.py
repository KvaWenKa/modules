import re

#list_str = ["45.77.169.140","146.19.215.133","dadadaefef","81.161.229.129","213.180.204.242","172.241.24.147","pwn.af","nazi.uy","automationyesterday.com","choserowboatfly.fun","threatfox.abuse.ch","nondutiable-rsh.initrdns.web-hosting.com","kniga-diva.ru","donate.v2.xmrig.com","b763cb6f604b03a162bc0a41c0a6df15","4996180b2fa1045aab5d36f46983e91dadeebfd4f765d69fa50eba4edf310acf","bc80b6983244855dc23257d3939165a249e4b18595d1650fb21a3dd3358920e2","87a7d1a01bdd0bba36e5e99136252e8d","d0e1074468166b69ea39ecd9afd68442","FAAE6F3632ECA46862DC41B434E78AC5"]

def filter(str):
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str) != None:
        ioc = {'type':'ip', 'data':re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str).string}
    elif re.search(r'^[0-9a-fA-F]{32}$', str) != None:
        ioc = {'type':'hash', 'data':re.search(r'^[0-9a-fA-F]{32}$', str).string}
    elif re.search(r"^[a-f0-9A-F]{64}(:.+)?$", str) != None:
        ioc = {'type':'hash', 'data':re.search(r"^[0-9a-fA-F]{64}(:.+)?$", str).string}
    elif re.search(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', str) != None:
        ioc = {'type':'domain', 'data':re.search(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', str).string}
    else:
        return None
    return ioc