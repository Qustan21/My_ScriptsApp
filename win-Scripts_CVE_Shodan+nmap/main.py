import os, requests, re, shodan, nmap, datetime, sys
from deep_translator import GoogleTranslator
from bs4 import BeautifulSoup
from urllib.parse import quote

# Исправление кодировки для Windows
if sys.platform == "win32":
    os.system('chcp 65001 > nul')
    sys.stdout.reconfigure(encoding='utf-8')

def show_help():
    now = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    print(f"""
\033[94m######################################################################
#                                                                    #
#               🛡️  CYBER ASSISTANT TERMINAL v3.7.2  🛡️              #
#                                                                    #
######################################################################\033[0m
\033[90mЗапуск системы: {now}\033[0m

\033[1mИНСТРУКЦИЯ ПО ЭКСПЛУАТАЦИИ:\033[0m

\033[92m[1] РЕЖИМ RECON (IP):\033[0m
   - Введи IP (напр. \033[93m8.8.8.8\033[0m). Shodan + Nmap + Mentor Advice.

\033[92m[2] РЕЖИМ CVE (Уязвимости):\033[0m
   - Введи номер (\033[93mCVE-2021-44228\033[0m). Описание NIST + Ссылка.

\033[95m[3] ПЕРЕВОДЧИК (tr):\033[0m
   - Напиши \033[1mtr\033[0m для перевода последнего вывода.

\033[94m----------------------------------------------------------------------
Команды: 'help' - помощь, 'exit' - выход.
----------------------------------------------------------------------\033[0m
""")

class CyberBot:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.nm = nmap.PortScanner(nmap_search_path=('nmap', 'nmap.exe', r'D:\System SETUP\Nmap\nmap.exe'))
        self.last_text = ""
        self.last_query = ""
        
        # РАСШИРЕННАЯ БАЗА ПЕНТЕСТЕРА
        self.port_data = {
            21: {"risk": "FTP: Передача данных без шифрования.", "next": "nmap --script ftp-anon -p 21"},
            22: {"risk": "SSH: Проверь на брутфорс и версию LibSSH.", "next": "hydra -L users.txt -P pass.txt ssh://[IP]"},
            23: {"risk": "Telnet: Перехват паролей в открытом виде.", "next": "tcpdump -ni eth0 port 23"},
            25: {"risk": "SMTP: Перечисление пользователей (VRFY/EXPN).", "next": "nmap --script smtp-enum-users -p 25"},
            53: {"risk": "DNS: Попробуй перенос зоны (AXFR).", "next": "dig axfr @[IP]"},
            80: {"risk": "HTTP: Веб-сервер. Ищи robots.txt и скрытые файлы.", "next": "gobuster dir -u http://[IP] -w common.txt"},
            111: {"risk": "RPCBind: Сбор данных о сетевых службах.", "next": "nmap -sV -p 111 --script=rpcinfo"},
            135: {"risk": "MSRPC: Сбор инфы об эндпоинтах Windows.", "next": "nmap --script msrpc-enum -p 135"},
            139: {"risk": "NetBIOS: Идентификация Windows-машин.", "next": "enum4linux -a [IP]"},
            161: {"risk": "SNMP: Сбор данных через 'public' community.", "next": "snmpwalk -v2c -c public [IP]"},
            389: {"risk": "LDAP: Риск перечисления данных Active Directory.", "next": "nmap --script ldap-search -p 389"},
            443: {"risk": "HTTPS: Изучи SSL сертификат (поддомены).", "next": "nmap --script ssl-enum-ciphers -p 443"},
            445: {"risk": "SMB: MS17-010 (EternalBlue) или Null Session.", "next": "nmap --script smb-vuln-ms17-010 -p 445"},
            514: {"risk": "Syslog: Может содержать логи с паролями.", "next": "nmap -sU -p 514 --script syslog-brute"},
            1433: {"risk": "MSSQL: Попробуй вход 'sa' без пароля.", "next": "nmap --script ms-sql-brute -p 1433"},
            1521: {"risk": "Oracle DB: Проверь стандартные TNS сиды.", "next": "nmap --script oracle-sid-brute -p 1521"},
            2049: {"risk": "NFS: Незащищенные сетевые папки.", "next": "showmount -e [IP]"},
            3306: {"risk": "MySQL: Проверь удаленный доступ root.", "next": "mysql -h [IP] -u root"},
            3389: {"risk": "RDP: Уязвимости BlueKeep / CredSSP.", "next": "nmap --script rdp-vuln-ms12-020 -p 3389"},
            5432: {"risk": "PostgreSQL: Дефолтный логин 'postgres'.", "next": "psql -h [IP] -U postgres"},
            5900: {"risk": "VNC: Удаленный доступ. Проверь пустой пароль.", "next": "nmap --script vnc-info -p 5900"},
            6379: {"risk": "Redis: Прямой доступ к памяти (NoAuth).", "next": "redis-cli -h [IP] info"},
            8080: {"risk": "HTTP-Alt: Панели управления (Tomcat/Jenkins).", "next": "nmap -sV --script http-enum -p 8080"},
            9200: {"risk": "ElasticSearch: Доступ к индексам данных.", "next": "curl -X GET http://[IP]:9200/_cat/indices"},
            27017: {"risk": "MongoDB: Доступ к коллекциям без пароля.", "next": "mongo --host [IP] --eval 'db.runCommand({listDatabases:1})'"}
        }

    def save_report(self):
        if not self.last_text: return
        choice = input("\n\033[93m[?] Сохранить результаты в отчет (.md)? (y/n): \033[0m").lower()
        if choice == 'y':
            base_dir = os.path.dirname(os.path.abspath(__file__))
            reports_dir = os.path.join(base_dir, "reports")
            if not os.path.exists(reports_dir): os.makedirs(reports_dir)
            
            safe_name = re.sub(r'[^a-zA-Z0-9а-яА-Я]', '_', self.last_query)[:30]
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            full_path = os.path.join(reports_dir, f"{safe_name}_{timestamp}.md")
            
            try:
                with open(full_path, "w", encoding="utf-8") as f:
                    # Заголовок отчета
                    f.write(f"# Cyber Report: {self.last_query}\n")
                    f.write(f"- **Дата:** {datetime.datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                    f.write(f"- **Цель:** `{self.last_query}`\n\n")
                    f.write("## 🔍 Результаты анализа\n\n")
                    
                    # Оформляем каждый раздел в блок кода или цитату
                    formatted_text = self.last_text
                    if "--- SHODAN DATA ---" in formatted_text:
                        formatted_text = formatted_text.replace("--- SHODAN DATA ---", "### 📡 Shodan Intelligence\n```yaml")
                        if "--- NMAP & MENTOR ADVICE ---" in formatted_text:
                            formatted_text = formatted_text.replace("--- NMAP & MENTOR ADVICE ---", "```\n\n### 🛡️ Nmap Scan & Mentor Advice\n```text")
                        formatted_text += "\n```"
                    else:
                        # Если это перевод CVE или другой текст
                        formatted_text = f"```text\n{formatted_text}\n```"

                    f.write(formatted_text)
                    f.write("\n\n---\n*Generated by Cyber Assistant v3.7.2*")
                
                print(f"\033[92m[+] Отчет сохранен красиво!\033[0m")
                os.startfile(full_path)
            except Exception as e: 
                print(f"[-] Ошибка записи: {e}")

    def get_cve_info(self, cve_id):
        self.last_query = cve_id
        print(f"[*] Запрос к NIST NVD API: {cve_id}...")
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            r = requests.get(url, timeout=10).json()
            desc = r['vulnerabilities'][0]['cve']['descriptions'][0]['value']
            self.last_text = f"CVE ID: {cve_id}\n\nDESCRIPTION:\n{desc}"
            print(f"\n\033[96m[CVE DATA]\033[0m\n{desc}")
            print(f"\033[94m[🔗] ПОДРОБНО: https://nvd.nist.gov/vuln/detail/{cve_id}\033[0m")
        except:
            print(f"[-] Ошибка API. Ссылка: https://nvd.nist.gov/vuln/detail/{cve_id}")

    def scan_ip(self, ip):
        self.last_query = ip
        print(f"\n[!] СТАРТ РАЗВЕДКИ: {ip}")
        report_parts = []
        try:
            host = self.api.host(ip)
            s_info = f"Org: {host.get('org', 'N/A')} | OS: {host.get('os', 'N/A')}\nPorts: {host.get('ports', [])}"
            print(f"\033[96m[SHODAN]\033[0m\n{s_info}")
            report_parts.append(f"--- SHODAN DATA ---\n{s_info}")
            
            print("[*] Активное сканирование Nmap...")
            port_list = ",".join(map(str, self.port_data.keys()))
            self.nm.scan(ip, port_list, arguments='-sV')
            
            if ip in self.nm.all_hosts():
                n_info = "\n--- NMAP & MENTOR ADVICE ---\n"
                for proto in self.nm[ip].all_protocols():
                    for port in sorted(self.nm[ip][proto].keys()):
                        state = self.nm[ip][proto][port]['state']
                        svc = self.nm[ip][proto][port].get('name', 'unknown')
                        ver = self.nm[ip][proto][port].get('product', '')
                        line = f"Port {port}/{proto}: {state} ({svc} {ver})"
                        print(line)
                        n_info += line + "\n"
                        if port in self.port_data and state == 'open':
                            advice = f"   💡 {self.port_data[port]['risk']}\n   🚀 Next: {self.port_data[port]['next']}"
                            print(f"\033[93m{advice}\033[0m")
                            n_info += advice + "\n"
                report_parts.append(n_info)
            self.last_text = "\n".join(report_parts)
            self.save_report()
        except Exception as e: print(f"[-] Ошибка Recon: {e}")

    def translate_last(self):
        if not self.last_text: 
            print("[-] Нечего переводить.")
            return
        print("[*] Перевод...")
        try:
            translated = GoogleTranslator(source='auto', target='ru').translate(self.last_text[:3000])
            print(f"\n--- [ ПЕРЕВОД ] ---\n{translated}")
            self.last_text = translated
            self.save_report()
        except Exception as e: print(f"[-] Ошибка перевода: {e}")

# Инициализация
bot = CyberBot("n4VpHTRMnG10R3EFFhDrk1rUKBUusb3Q")
show_help()

while True:
    cmd = input("\n\033[92m[CyberHub]>\033[0m ").strip()
    if not cmd: continue
    if cmd.lower() == 'exit': break
    if cmd.lower() == 'help': show_help()
    elif cmd.lower() == 'tr': bot.translate_last()
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cmd): bot.scan_ip(cmd)
    elif cmd.upper().startswith("CVE-"): bot.get_cve_info(cmd.upper())
    else: print("[-] Неизвестная команда. Введите IP, CVE или 'help'.")