import json
import telebot
import logging
from filter import filter
from virustotal import parser_virus_total
from kaspersky import parser_kasperskyTI
from criminalip import parser_criminalip
from abuseipdb import parser_abuseip
from alienvult import parser_alienvault

text_info = '''VT (Virus Total)
🟢GREEN - 0 malicious
🟡YELLOW - 1-3 malicious
🔴RED - >3 malicious
REPUTATION - Голоса пользователей

KIT (Kaspersky TIP)
🟢GREEN - Green Zone
🟡YELLOW - Grey, Yellow, Orange Zone
🔴RED - Red Zone
REPUTATION - Количество обращений к запрашиваемому веб-адресу, обнаруженных экспертными системами "Лаборатории Касперского".

CIP (Criminal IP)
🟢GREEN - < 25% IP Scoring
🟡YELLOW - < 75% IP Scoring
🔴RED - > 75% IP Scoring
REPUTATION - Кол-во репортов 

AIPDB (AbuseIPDB)
🟢GREEN - 0 AbuseScore и нет репортов
🟡YELLOW - 0 AbuseScore и есть репорты
🔴RED - > 0 AbuseScore
REPUTATION - Кол-во репортов 

AV (Alien Vult)
🟢GREEN - Есть старые пульсы
🟡YELLOW - Есть пульсы не старше года 
🔴RED - Есть пульсы не старше трех месяцев
REPUTATION - Кол-во пульсов'''

#ioc = {'type':'ip', 'data':'195.69.202.145'}
#ioc = {'type':'domain', 'data':'submit-form.com'}
#ioc = {'type':'hash', 'data':'7bcdc2e607abc65ef93afd009c3048970d9e8d1c2a18fc571562396b13ebb301'}

logging.basicConfig(level=logging.INFO, filename="py_log.log",filemode="a",
                    format="%(asctime)s %(levelname)s %(message)s")

BOT_TOKEN = '6125269266:AAH6C_lv41DEl_C0r8rAN5oayfua3T7KE88'
bot = telebot.TeleBot(BOT_TOKEN)

@bot.message_handler(commands=['info'])
def start(message):
    bot.send_message(message.from_user.id, text_info)

@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(message.from_user.id, "Enter IPv4, DOMAIN, HASH")

def report_builder(ioc):
    data = []
    vendor_data = parser_virus_total(ioc)
    if vendor_data != None:
        print("ADD VT")
        data.append(vendor_data)
    vendor_data = parser_kasperskyTI(ioc)
    if vendor_data != None:
        print("ADD KTI")
        data.append(vendor_data)
    vendor_data = parser_criminalip(ioc)
    if vendor_data != None:
        print("ADD CIP")
        data.append(vendor_data)
    vendor_data = parser_abuseip(ioc)
    if vendor_data != None:
        print("ADD AIP")
        data.append(vendor_data)
    vendor_data = parser_alienvault(ioc)
    if vendor_data != None:
        print("ADD AV")
        data.append(vendor_data)

    final_report = {'verdict':{},
                    'reputation':{}}
    for ven in data:
        for row in ven:
            if row in final_report:
                if row in ['verdict', 'reputation']:
                    final_report[row][ven['vendor']] = ven[row]
                elif isinstance(ven[row], str) and not ven[row] in final_report[row]:
                    final_report[row].append(ven[row])
                elif isinstance(ven[row], list):
                    final_report[row] += ven[row]
                elif isinstance(ven[row], int) and ven[row] > final_report[row]:
                    final_report[row] = ven[row]
            else:
                if isinstance(ven[row], str):
                    final_report[row] = []
                    final_report[row].append(ven[row])
                else:
                    final_report[row] = ven[row]

    c = {'green': 0, 'yellow': 1, 'red': len(final_report['verdict'])}
    k = 0
    for report in final_report['verdict'].keys():
            k += c[final_report['verdict'][report]]
    final_report["significance_factor"] = k / len(final_report['verdict'])

    if final_report["significance_factor"] > 1:
        final_report["overall_verdict"] = 'RED'
    elif final_report["significance_factor"] > len(final_report['verdict'])*0.2:
        final_report["overall_verdict"] = 'YELLOW'
    else:
        final_report["overall_verdict"] = 'GREEN'
    return final_report

@bot.message_handler(content_types=['text'])
def get_text_messages(message):
    emogi = {'RED':'🔴','YELLOW':'🟡','GREEN':'🟢'}
    logging.info(f"GET messege from {message.from_user.id} : \'{message.text}\' ")
    ioc = filter(message.text)
    if ioc == None:
        bot.send_message(message.from_user.id, '🚫Тип индикатора не определен')
        logging.warning(f"Indicator type is not defined \'{message.text}\'")
    else:
        print(ioc)
        bot.send_message(message.from_user.id, '✅Принято в обработку')
        final_report = report_builder(ioc)
        text_bot = f"{final_report['value']['data']} ({final_report['value']['type']})\n"
        text_bot += f"VERDICT = {final_report['overall_verdict']}{emogi[final_report['overall_verdict']]}\n"
        text_bot += f"significance =  {final_report['significance_factor']}\n"
        for vendor in final_report['verdict'].keys():
            text_bot += f"{vendor}: {emogi[final_report['verdict'][vendor].upper()]}, "
        text_bot +="\n\n"
        
        for name in final_report.keys():
            if name not in ['value', 'overall_verdict', 'significance_factor']:
                text_bot += f'{name.upper()} : {final_report[name]}\n'
        bot.send_message(message.from_user.id, text_bot)
        logging.info(f"SEND messege to {message.from_user.id}")
bot.polling(none_stop=True, interval=0)


#with open('IOC_data.json', 'w') as outfile:
#    json.dump(data, outfile)