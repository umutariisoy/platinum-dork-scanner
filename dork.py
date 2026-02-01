import sys
import os
import threading
import time
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# --- KÜTÜPHANE KONTROLÜ ---
try:
    import requests
    from fake_useragent import UserAgent
except ImportError:
    import tkinter.messagebox as msg
    root = tk.Tk()
    root.withdraw()
    msg.showerror("Kritik Hata", "Eksik kütüphaneler var.\nLütfen terminale şunu yaz: pip install requests fake-useragent")
    sys.exit()

# --- AYARLAR & FİLTRELER ---

# 1. ÇÖP DOSYALAR (Asla Gösterme)
BANNED_EXTENSIONS = (
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.avi', '.mov',
    '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.csv',
    '.xml', '.json', '.txt', '.map', '.min.js'
)

# 2. ÇÖP KLASÖRLER
BANNED_KEYWORDS = (
    '/assets/', '/static/', '/wp-content/themes/', '/wp-includes/js/',
    '/node_modules/', '/bower_components/', '/cache/', '/tmp/',
    'jquery', 'bootstrap', 'fontawesome', '/lib/', '/vendor/', '/images/'
)

# 3. DURDURUCU KELİMELER (Stop Words)
STOP_WORDS = {
    'the', 'and', 'for', 'of', 'to', 'in', 'is', 'on', 'at', 'by', 'my',
    'web', 'www', 'com', 'net', 'org', 'http', 'https', 'html', 'htm',
    'site', 'url', 'file', 'index', 'page', 'home', 'default', 'main'
}

# 4. KRİTİK UZANTILAR (Her zaman göster ve Kırmızı yap)
CRITICAL_EXTENSIONS = (
    '.env', '.sql', '.log', '.bak', '.old', '.config', '.ini',
    '.db', '.dat', '.pem', '.key', '.secret', 'wp-config', '.zip', '.rar'
)

# 5. ZAYIF UZANTILAR (V14 YENİLİĞİ)
# Bu uzantılar, ancak "INTERESTING_KEYWORDS" ile birleşirse gösterilir.
# Yoksa contact.html gibi gereksiz sonuçlar çıkar.
WEAK_EXTENSIONS = (
    '.html', '.htm', '.php', '.asp', '.aspx', '.jsp'
)

# 6. İLGİ ÇEKİCİ KELİMELER (Zayıf uzantıları kurtaran kelimeler)
INTERESTING_KEYWORDS = (
    'admin', 'login', 'user', 'dashboard', 'config', 'test', 'backup',
    'shell', 'upload', 'panel', 'auth', 'account', 'member', 'db',
    'database', 'install', 'setup', 'beta', 'dev', 'prod', 'staging',
    'secret', 'token', 'api', 'debug', 'monitor'
)

class PlatinumEngine:
    def __init__(self, log_callback):
        self.log = log_callback
        self.session = requests.Session()
        self.ua = UserAgent()
        self.unique_urls = set()
        self.stop_event = False

    def is_clean_url(self, url):
        try:
            url_lower = url.lower().split('?')[0]
            if url_lower.endswith(BANNED_EXTENSIONS): return False
            for bw in BANNED_KEYWORDS:
                if bw in url_lower: return False
            return True
        except: return False

    # --- KAYNAKLAR ---
    def fetch_archive(self, domain):
        if self.stop_event: return
        self.log(f"[*] [WAYBACK] Archive.org Geçmişi Taranıyor...", 'info')
        # Limit 50.000 yapıldı
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&filter=statuscode:200&limit=50000"
        try:
            resp = self.session.get(url, headers={'User-Agent': self.ua.random}, timeout=60)
            if resp.status_code == 200:
                count = 0
                for line in resp.text.splitlines():
                    raw_url = line.strip()
                    if self.is_clean_url(raw_url):
                        self.unique_urls.add(raw_url)
                        count += 1
                self.log(f"   [+] Wayback Machine: {count} temiz URL.", 'success')
            else:
                self.log(f"   [-] Wayback Yanıt: {resp.status_code}", 'error')
        except Exception as e:
            self.log(f"   [-] Wayback Hatası: {e}", 'error')

    def fetch_hackertarget(self, domain):
        if self.stop_event: return
        self.log(f"[*] [API] HackerTarget Subdomains...", 'info')
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.session.get(url, timeout=20)
            count = 0
            for line in resp.text.splitlines():
                parts = line.split(',')
                if len(parts) > 0:
                    sub = parts[0]
                    self.unique_urls.add(f"http://{sub}")
                    self.unique_urls.add(f"https://{sub}")
                    count += 1
            self.log(f"   [+] HackerTarget: {count} subdomain.", 'success')
        except: self.log("   [-] HackerTarget yanıt vermedi.", 'error')

    def fetch_alienvault(self, domain):
        if self.stop_event: return
        self.log(f"[*] [OTX] AlienVault Deep Scan...", 'info')
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1"
            resp = self.session.get(url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                count = 0
                if 'url_list' in data:
                    for item in data['url_list']:
                        raw_url = item.get('url', '')
                        if self.is_clean_url(raw_url):
                            self.unique_urls.add(raw_url)
                            count += 1
                self.log(f"   [+] AlienVault: {count} temiz URL.", 'success')
        except: self.log("   [-] AlienVault yanıt vermedi.", 'error')

    def harvest(self, domain):
        with ThreadPoolExecutor(max_workers=3) as executor:
            f1 = executor.submit(self.fetch_archive, domain)
            f2 = executor.submit(self.fetch_hackertarget, domain)
            f3 = executor.submit(self.fetch_alienvault, domain)
            f1.result(); f2.result(); f3.result()
        return len(self.unique_urls)

    def match_dorks(self, dork_list, target_domain):
        matches = []
        if not self.unique_urls: return matches

        self.log(f"\n[*] PLATINUM ANALİZ BAŞLADI: {len(self.unique_urls)} URL x {len(dork_list)} Dork", 'system')
        
        domain_root = target_domain.split('.')[0]
        
        for dork_raw in dork_list:
            if self.stop_event: break
            dork = dork_raw.strip()
            if len(dork) < 3: continue
            
            term = ""
            mode = "generic"
            
            try:
                if "inurl:" in dork:
                    parts = dork.split("inurl:")[1].strip()
                    term = parts.split(" ")[0].replace('"', '').replace("'", "")
                    mode = "inurl"
                elif "filetype:" in dork or "ext:" in dork:
                    raw_ext = dork.split("type:")[1] if "type:" in dork else dork.split("ext:")[1]
                    term = "." + raw_ext.strip().split(" ")[0].replace(".", "")
                    mode = "ext"
                else:
                    parts = [p for p in dork.split(" ") if "site:" not in p and "intitle:" not in p and "intext:" not in p]
                    if parts:
                        term = parts[0].replace('"', '').replace("'", "").strip()
                        mode = "path"

                if not term or len(term) < 3: continue
                
                term_lower = term.lower()
                if term_lower in STOP_WORDS: continue
                if term_lower in domain_root.lower(): continue

            except: continue

            # --- EŞLEŞTİRME & ZAYIF UZANTI KONTROLÜ ---
            term = term.lower()
            
            for url in self.unique_urls:
                url_lower = url.lower()
                
                try:
                    parsed = urllib.parse.urlparse(url_lower)
                    url_path_only = parsed.path + "?" + parsed.query
                except: url_path_only = url_lower

                is_match = False
                
                # EXT Modu Eşleşmesi
                if mode == "ext":
                    base_url = url_lower.split('?')[0]
                    if base_url.endswith(term):
                        is_match = True
                        
                        # V14 KRİTİK FİLTRE:
                        # Eğer uzantı ZAYIF ise (html, php vb.) ve URL içinde
                        # İLGİNÇ BİR KELİME YOKSA, bunu eşleşme sayma!
                        if term in WEAK_EXTENSIONS:
                            has_interesting = False
                            for kw in INTERESTING_KEYWORDS:
                                if kw in url_path_only:
                                    has_interesting = True
                                    break
                            if not has_interesting:
                                is_match = False # contact.html gibi dosyaları ele

                # Path/Inurl Modu Eşleşmesi
                elif mode == "inurl" or mode == "path":
                    if term in url_path_only:
                        is_match = True
                
                if is_match:
                    severity = "NORMAL"
                    # Kritiklik Kontrolü
                    if any(c in url_lower for c in CRITICAL_EXTENSIONS):
                        severity = "CRITICAL" # En yüksek seviye
                    elif "admin" in term or "login" in term or "config" in term or "dashboard" in term:
                        severity = "HIGH"
                    
                    matches.append({
                        'url': url,
                        'dork': dork,
                        'term': term,
                        'type': mode.upper(),
                        'severity': severity
                    })

        # Tekilleştirme
        unique_matches = []
        seen_urls = set()
        for m in matches:
            if m['url'] not in seen_urls:
                seen_urls.add(m['url'])
                unique_matches.append(m)
        
        # Sıralama: CRITICAL > HIGH > NORMAL
        severity_order = {"CRITICAL": 3, "HIGH": 2, "NORMAL": 1}
        unique_matches.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=True)
                
        return unique_matches

# --- GUI ---

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Google Dork V14 - PLATINUM EDITION (Industrial Standard)")
        self.root.geometry("1200x850")
        self.root.configure(bg="#080808")

        self.dorks = []
        self.engine = None
        self.results = []
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Header
        header = tk.Frame(self.root, bg="#000")
        header.pack(fill="x")
        
        tk.Label(header, text=" PLATINUM SCANNER ", font=("Impact", 35), bg="#000", fg="#e5e5e5").pack(side="left", padx=10, pady=10)
        tk.Label(header, text="V14 FINAL", font=("Arial", 12, "bold"), bg="#000", fg="#888").pack(side="left", pady=25)
        
        # Kontrol
        ctrl = tk.LabelFrame(self.root, text=" TARGET SYSTEM ", bg="#0f0f0f", fg="#e5e5e5", bd=1, relief="solid", font=("Arial", 10, "bold"))
        ctrl.pack(fill="x", padx=15, pady=10)

        tk.Label(ctrl, text="TARGET DOMAIN :", bg="#0f0f0f", fg="#ccc", font=("Consolas", 11)).grid(row=0, column=0, padx=15, pady=20, sticky="e")
        self.entry_target = tk.Entry(ctrl, width=45, bg="#1a1a1a", fg="#fff", insertbackground="#fff", font=("Consolas", 13), borderwidth=0)
        self.entry_target.insert(0, "jackbit.com")
        self.entry_target.grid(row=0, column=1, pady=20)

        tk.Button(ctrl, text="LOAD DORKS", command=self.load_file, bg="#333", fg="#fff", font=("Arial", 9, "bold"), height=2, width=20, borderwidth=0).grid(row=0, column=2, padx=20)
        self.lbl_file = tk.Label(ctrl, text="NO FILE", bg="#0f0f0f", fg="#555", font=("Arial", 9))
        self.lbl_file.grid(row=0, column=3)

        # Başlat
        self.btn_start = tk.Button(self.root, text="► START PLATINUM ENGINE", command=self.start_thread, bg="#e5e5e5", fg="#000", font=("Segoe UI", 12, "bold"), height=2, borderwidth=0)
        self.btn_start.pack(fill="x", padx=15, pady=5)

        # Log
        term_frame = tk.Frame(self.root, bg="#080808")
        term_frame.pack(fill="both", expand=True, padx=15, pady=10)
        self.txt_log = scrolledtext.ScrolledText(term_frame, bg="#000", fg="#ccc", font=("Consolas", 10), borderwidth=0)
        self.txt_log.pack(fill="both", expand=True)
        
        self.txt_log.tag_config('info', foreground='#00ccff')
        self.txt_log.tag_config('success', foreground='#00ff00')
        self.txt_log.tag_config('error', foreground='#ff3333')
        self.txt_log.tag_config('system', foreground='#ffff00')
        self.txt_log.tag_config('critical', foreground='#fff', background='#cc0000') # Koyu Kırmızı
        self.txt_log.tag_config('high', foreground='#000', background='#ffcc00') # Sarı
        self.txt_log.tag_config('normal', foreground='#ccc')

        self.btn_save = tk.Button(self.root, text="⇩ EXPORT REPORT", command=self.save, bg="#222", fg="#fff", state="disabled", font=("Arial", 10, "bold"), height=2, borderwidth=0)
        self.btn_save.pack(fill="x", padx=15, pady=15)

    def log(self, msg, tag='info'):
        self.txt_log.config(state='normal')
        self.txt_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)
        self.txt_log.see(tk.END)
        self.txt_log.config(state='disabled')

    def load_file(self):
        path = filedialog.askopenfilename()
        if path:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                self.dorks = [l.strip() for l in f if len(l.strip()) > 3]
            self.lbl_file.config(text=f"{len(self.dorks)} DORKS", fg="#fff")

    def start_thread(self):
        target = self.entry_target.get().strip()
        if not target or not self.dorks:
            messagebox.showwarning("Hata", "Hedef ve dosya gerekli.")
            return

        self.btn_start.config(state="disabled", bg="#333", text="PROCESSING...")
        self.txt_log.config(state='normal')
        self.txt_log.delete(1.0, tk.END)
        self.txt_log.config(state='disabled')
        threading.Thread(target=self.run_platinum, args=(target,), daemon=True).start()

    def run_platinum(self, target):
        self.engine = PlatinumEngine(self.log)
        
        self.log(f"=== PLATINUM ENGINE: {target} ===", 'system')
        self.log(f"=== FAZ 1: DERİN URL HASADI ===", 'system')
        
        total = self.engine.harvest(target)
        if total == 0:
            self.log("[-] URL bulunamadı.", 'error')
            self.reset_ui()
            return

        self.log(f"[+] HAVUZ: {total} benzersiz URL.", 'success')
        self.log(f"=== FAZ 2: DORK & CONTEXT FILTER ===", 'system')
        
        matches = self.engine.match_dorks(self.dorks, target)
        self.results = matches
        
        crit_count = sum(1 for m in matches if m['severity'] == "CRITICAL")
        high_count = sum(1 for m in matches if m['severity'] == "HIGH")
        
        if matches:
            self.log(f"\n[!!!] TARAMA BİTTİ: {len(matches)} SONUÇ [!!!]", 'success')
            self.log(f"[!!!] KRİTİK: {crit_count} | YÜKSEK: {high_count}", 'success')
            
            for m in matches:
                tag = 'normal'
                prefix = "[INFO]"
                if m['severity'] == "CRITICAL": tag = 'critical'; prefix = "[CRIT]"
                elif m['severity'] == "HIGH": tag = 'high'; prefix = "[HIGH]"
                
                self.log(f" {prefix} -> {m['url']}", tag)
                self.log(f"        (Term: '{m['term']}' | Type: {m['type']})", 'info')
                
            self.btn_save.config(state="normal", bg="#008800")
        else:
            self.log("\n[-] Eşleşme yok. Gürültü filtresi tüm zayıf sonuçları eledi.", 'error')

        self.reset_ui()
        messagebox.showinfo("Bitti", f"Tarama Tamamlandı.\nBulunan: {len(matches)}\nKritik: {crit_count}")

    def reset_ui(self):
        self.btn_start.config(state="normal", bg="#e5e5e5", text="► START PLATINUM ENGINE")

    def save(self):
        if not self.results: return
        path = filedialog.asksaveasfilename(defaultextension=".html", initialfile="V14_Platinum_Report.html")
        if path:
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>V14 PLATINUM REPORT</title>
                <style>
                    body { background-color: #111; color: #ccc; font-family: 'Segoe UI', sans-serif; padding: 20px; }
                    h1 { color: #fff; border-bottom: 2px solid #333; }
                    .stats { background: #222; padding: 10px; margin-bottom: 20px; border-radius: 5px; color: #fff; }
                    .card { background: #1a1a1a; padding: 15px; margin-bottom: 10px; border-left: 5px solid #444; }
                    .card.CRITICAL { border-left: 5px solid #ff0000; background: #2a0000; color: #fff; }
                    .card.HIGH { border-left: 5px solid #ffcc00; background: #2a2200; color: #fff; }
                    a { color: #fff; text-decoration: none; font-size: 16px; display: block; margin-bottom: 5px;}
                    a:hover { color: #ccc; text-decoration: underline; }
                    .meta { font-size: 12px; color: #888; }
                    .tag { padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; }
                    .tag.CRITICAL { background: #ff0000; color: #fff; }
                    .tag.HIGH { background: #ffcc00; color: #000; }
                    .tag.NORMAL { background: #444; color: #fff; }
                </style>
            </head>
            <body>
                <h1>V14 PLATINUM REPORT</h1>
                <div class="stats">Target: """ + self.entry_target.get() + """ | Total: """ + str(len(self.results)) + """</div>
            """
            for m in self.results:
                html += f"""
                <div class="card {m['severity']}">
                    <span class="tag {m['severity']}">{m['severity']}</span>
                    <a href="{m['url']}" target="_blank">{m['url']}</a>
                    <div class="meta">Matched Term: <b>{m['term']}</b> | Type: {m['type']} | Dork: {m['dork']}</div>
                </div>
                """
            html += "</body></html>"
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            webbrowser.open(path)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()