import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import random
import re
import sys
import socket
import struct
import os
import binascii
import shutil 
import subprocess
import csv
import ctypes
import math
import json
import queue
from collections import deque 
import concurrent.futures

# --- IMPORTAÇÕES ADICIONAIS ---
import webbrowser
try:
    import requests
except ImportError:
    pass

# --- VERIFICAÇÃO NMAP ---
try:
    import nmap
    HAS_NMAP_LIB = True
except ImportError:
    HAS_NMAP_LIB = False


# --- NÍVEIS DE AMEAÇA ---
class ThreatLevel:
    SAFE = "Seguro"
    LOW = "Baixo"
    MEDIUM = "Médio"
    HIGH = "Alto"
    CRITICAL = "Crítico"


class ScoutGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Scout OSINT Toolkit v2.5 Pro - ({sys.platform})")
        self.root.geometry("1400x900")
        
        # --- FILA DE EVENTOS GUI ---
        self.ui_queue = queue.Queue()
        self.process_ui_queue()

        # --- PRIVILÉGIOS ---
        self.ensure_admin_rights()

        # --- CAMINHOS WINDOWS ---
        if sys.platform == "win32":
            nmap_paths = [
                r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap",
                os.path.expanduser(r"~\AppData\Local\Programs\Nmap")
            ]
            for path in nmap_paths:
                if os.path.exists(path) and path not in os.environ.get('PATH', ''):
                    os.environ['PATH'] += ";" + path

        # --- VARIÁVEIS DE ESTADO ---
        self.sniffing_active = False
        self.behavior_active = False
        self.monitor_mode_enabled = False 
        
        self.filter_ip_str = tk.StringVar()
        self.filter_category = tk.StringVar(value="TODOS")
        self.selected_interface = tk.StringVar(value="Auto / Default")
        self.lan_target = tk.StringVar(value="192.168.1.0/24")
        
        self.stat_pkt_count = tk.IntVar(value=0)
        self.stat_data_vol = tk.StringVar(value="0 KB")
        self.total_bytes = 0
        
        # --- ESTRUTURAS DE DADOS ---
        self.active_nmap_targets = set() 
        self.dns_cache = {} 
        self.active_connections = {} 
        self.latest_activity = {}
        
        self.tree_colors = {"TCP": "#00ffff", "UDP": "#ffcc00", "ICMP": "#ff00ff", "OTHER": "white"}
        
        self.resolver_executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

        # --- TEMAS ---
        self.themes = {
            "Dark (Padrão)": {"bg": "#1e1e1e", "fg": "white", "btn": "#007acc", "log_bg": "#000000", "log_fg": "#00ff00", "tree_bg": "#2d2d2d", "tree_fg": "white", "head_bg": "#333", "head_fg": "white"},
            "Light (Claro)": {"bg": "#f0f0f0", "fg": "black", "btn": "#005f9e", "log_bg": "white", "log_fg": "black", "tree_bg": "white", "tree_fg": "black", "head_bg": "#ddd", "head_fg": "black"},
            "Hacker Green": {"bg": "#0d0d0d", "fg": "#00ff00", "btn": "#004400", "log_bg": "#001100", "log_fg": "#00ff00", "tree_bg": "#001100", "tree_fg": "#00ff00", "head_bg": "#002200", "head_fg": "#00ff00"},
        }
        self.current_theme_name = tk.StringVar(value="Dark (Padrão)")

        # --- INICIALIZAÇÃO DA INTERFACE ---
        self.apply_theme(self.themes["Dark (Padrão)"])
        self.build_ui()
        self.detect_local_ip()
        self.root.after(1000, self.check_and_install_dependencies)

    def process_ui_queue(self):
        try:
            for _ in range(50):
                if self.ui_queue.empty():
                    break
                task = self.ui_queue.get_nowait()
                task()
        except Exception as e:
            print(f"Erro na fila UI: {e}")
        finally:
            self.root.after(100, self.process_ui_queue)

    def enqueue_ui_task(self, task_func):
        self.ui_queue.put(task_func)

    def ensure_admin_rights(self):
        try:
            if sys.platform == 'win32':
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                    sys.exit()
        except Exception as e:
            print(f"Erro de privilégios: {e}")

    def detect_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            base_ip = ".".join(local_ip.split(".")[:3]) + ".0/24"
            self.lan_target.set(base_ip)
            self.log(f"Rede detetada: {base_ip} (Interface: {local_ip})", "sucesso")
            return local_ip
        except Exception:
            self.lan_target.set("192.168.0.0/24")
            return "127.0.0.1"

    def build_ui(self):
        # --- CABEÇALHO ---
        self.header_frame = ttk.Frame(self.root)
        self.header_frame.pack(fill="x", padx=10, pady=10)
        tk.Label(self.header_frame, text="SCOUT OSINT TOOLKIT - PRO EDITION", font=("Consolas", 20, "bold")).pack()
        
        status_text = f"Sistema: {sys.platform} | Privilégios: {'ELEVADOS' if self.is_admin_check() else 'LIMITADOS'}"
        tk.Label(self.header_frame, text=status_text, font=("Consolas", 10), fg="#aaaaaa").pack()

        # --- ABAS PRINCIPAIS ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=5)
        
        if sys.platform.startswith('linux'):
            self.tab_wifi = ttk.Frame(self.notebook)
            self.notebook.add(self.tab_wifi, text="📡 WiFi & Monitorização")
            self.setup_wifi_tab()

        self.tab_sniffer = ttk.Frame(self.notebook); self.notebook.add(self.tab_sniffer, text="📊 Monitor de Tráfego")
        self.setup_sniffer_tab()

        self.tab_behavior = ttk.Frame(self.notebook); self.notebook.add(self.tab_behavior, text="🧠 Motor Comportamental")
        self.setup_behavior_tab()

        self.tab_lan = ttk.Frame(self.notebook); self.notebook.add(self.tab_lan, text="🏠 Scanner de Rede (LAN)")
        self.setup_lan_tab()

        self.tab_domain = ttk.Frame(self.notebook); self.notebook.add(self.tab_domain, text="🔎 WHOIS & Domínios")
        self.setup_domain_tab()

        self.tab_tools = ttk.Frame(self.notebook); self.notebook.add(self.tab_tools, text="🛠️ Ferramentas")
        self.setup_tools_tab()
        
        self.tab_config = ttk.Frame(self.notebook); self.notebook.add(self.tab_config, text="⚙️ Configurações")
        self.setup_config_tab()

        # --- ÁREA DE REGISTOS ---
        self.log_frame = ttk.Frame(self.root)
        self.log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(self.log_frame, text="REGISTO DE OPERAÇÕES (LOGS):", font=("Consolas", 10, "bold")).pack(anchor="w")
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=8, font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True)
        
        self.update_theme_colors()

    # --- UTILITÁRIOS ---
    def is_admin_check(self):
        try:
            return os.getuid() == 0 if sys.platform != 'win32' else ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception: 
            return False

    def check_and_install_dependencies(self):
        try:
            import requests
        except ImportError:
            if messagebox.askyesno("Dependências", "A biblioteca 'requests' está em falta. Instalar agora?"):
                 try: 
                     subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
                     messagebox.showinfo("Reinício", "Biblioteca instalada. Por favor, reinicie a aplicação.")
                 except Exception as e: 
                     self.log(f"Erro na instalação: {e}", "erro")

        if not HAS_NMAP_LIB:
            if messagebox.askyesno("Dependências", "Instalar python-nmap?"):
                try: 
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"])
                    messagebox.showinfo("OK", "Instalado com sucesso. Reinicie a ferramenta.")
                except Exception as e: 
                    self.log(f"Erro na instalação: {e}", "erro")
        
        if not shutil.which("nmap"):
            paths = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
            if not any(os.path.exists(p) for p in paths):
                if messagebox.askyesno("Nmap", "Executável do Nmap não encontrado. Deseja descarregar?"): 
                    webbrowser.open("https://nmap.org/download.html")

    # --- ABA 1: SNIFFER ---
    def setup_sniffer_tab(self):
        f = ttk.Frame(self.tab_sniffer); f.pack(fill="both", expand=True, padx=20, pady=20)
        
        dash = ttk.LabelFrame(f, text="Estatísticas em Tempo Real"); dash.pack(fill="x", padx=5)
        ttk.Label(dash, text="Pacotes:").pack(side="left", padx=10)
        ttk.Label(dash, textvariable=self.stat_pkt_count, foreground="#00ff00", font=("Consolas", 12, "bold")).pack(side="left")
        ttk.Label(dash, text="| Volume:").pack(side="left", padx=10)
        ttk.Label(dash, textvariable=self.stat_data_vol, foreground="#00ccff", font=("Consolas", 12, "bold")).pack(side="left")

        ctrl = ttk.Frame(f); ctrl.pack(fill="x", pady=10)
        self.btn_start = ttk.Button(ctrl, text="▶ INICIAR CAPTURA", command=self.start_sniffing); self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(ctrl, text="⏹ PARAR", command=self.stop_sniffing, state="disabled"); self.btn_stop.pack(side="left", padx=5)
        
        ttk.Button(ctrl, text="💾 Exportar CSV", command=self.export_sniffer_csv).pack(side="right", padx=5)
        ttk.Button(ctrl, text="🗑️ Limpar Ecrã", command=self.clear_sniffer_data).pack(side="right", padx=5)

        filt = ttk.Frame(f); filt.pack(fill="x", pady=5)
        if sys.platform.startswith('linux'):
            ttk.Label(filt, text="Interface:").pack(side="left")
            self.combo_iface = ttk.Combobox(filt, textvariable=self.selected_interface, values=self.get_network_interfaces(), width=10)
            self.combo_iface.pack(side="left", padx=5)
        
        ttk.Label(filt, text="Filtro de IP:").pack(side="left")
        ttk.Entry(filt, textvariable=self.filter_ip_str, width=15).pack(side="left", padx=5)
        
        ttk.Label(filt, text="Categoria:").pack(side="left")
        self.combo_cat = ttk.Combobox(filt, textvariable=self.filter_category, values=["TODOS", "Media", "Web", "Game", "Outros"], state="readonly", width=10)
        self.combo_cat.pack(side="left", padx=5)
        ttk.Button(filt, text="Aplicar Filtro", command=self.refresh_tree_filter).pack(side="left")

        cols = ("src", "dst", "proto", "context", "count", "last")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=15)
        self.tree.heading("src", text="Origem"); self.tree.column("src", width=130, anchor="center")
        self.tree.heading("dst", text="Destino"); self.tree.column("dst", width=130, anchor="center")
        self.tree.heading("proto", text="Protocolo"); self.tree.column("proto", width=70, anchor="center")
        self.tree.heading("context", text="Contexto / Payload (SNI)"); self.tree.column("context", width=350, anchor="w")
        self.tree.heading("count", text="Qtd."); self.tree.column("count", width=50, anchor="center")
        self.tree.heading("last", text="Visto em"); self.tree.column("last", width=80, anchor="center")
        self.tree.pack(fill="both", expand=True)
        
        sb = ttk.Scrollbar(f, orient="vertical", command=self.tree.yview)
        sb.place(relx=0.985, rely=0.3, relheight=0.68, anchor="ne")
        self.tree.configure(yscrollcommand=sb.set)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-1>", self.on_tree_double_click)

    def clear_sniffer_data(self):
        self.active_connections.clear()
        self.tree.delete(*self.tree.get_children())
        self.tree_behavior.delete(*self.tree_behavior.get_children())
        self.stat_pkt_count.set(0)
        self.total_bytes = 0
        self.stat_data_vol.set("0 KB")
        self.log("Dados do sniffer limpos da memória.", "info")

    # --- ABA 2: COMPORTAMENTO ---
    def setup_behavior_tab(self):
        f = ttk.Frame(self.tab_behavior); f.pack(fill="both", expand=True, padx=20, pady=20)
        ttk.Label(f, text="Motor Heurístico de Ameaças (NBA) - Inspeção SNI e Análise de Fluxo", font=("Consolas", 12), foreground="#ffaa00").pack(pady=10)
        cols = ("src", "dst", "proto", "behavior", "details", "confidence")
        self.tree_behavior = ttk.Treeview(f, columns=cols, show="headings", height=18)
        self.tree_behavior.heading("src", text="Origem")
        self.tree_behavior.heading("dst", text="Destino")
        self.tree_behavior.heading("proto", text="Proto")
        self.tree_behavior.heading("behavior", text="Comportamento Detetado")
        self.tree_behavior.heading("details", text="Estatísticas (Detalhes)")
        self.tree_behavior.heading("confidence", text="Nível de Risco")
        
        self.tree_behavior.column("confidence", width=120, anchor="center")
        self.tree_behavior.pack(fill="both", expand=True)

    # --- ABA 3: LAN SCANNER ---
    def setup_lan_tab(self):
        f = ttk.Frame(self.tab_lan); f.pack(fill="both", expand=True, padx=20, pady=20)
        ctrl = ttk.LabelFrame(f, text="Scanner de Dispositivos"); ctrl.pack(fill="x")
        ttk.Label(ctrl, text="Alvo (IP/CIDR):").pack(side="left", padx=10)
        ttk.Entry(ctrl, textvariable=self.lan_target).pack(side="left")
        self.btn_scan = ttk.Button(ctrl, text="ESCANEAR REDE", command=self.run_lan_scan)
        self.btn_scan.pack(side="left", padx=10)
        
        cols = ("ip", "mac", "vendor", "hostname", "status")
        self.tree_lan = ttk.Treeview(f, columns=cols, show="headings", height=18)
        self.tree_lan.heading("ip", text="Endereço IP")
        self.tree_lan.heading("mac", text="Endereço MAC")
        self.tree_lan.heading("vendor", text="Fabricante da Placa")
        self.tree_lan.heading("hostname", text="Nome do Dispositivo")
        self.tree_lan.heading("status", text="Estado")
        self.tree_lan.pack(fill="both", expand=True)

    def run_lan_scan(self):
        tgt = self.lan_target.get()
        self.tree_lan.delete(*self.tree_lan.get_children())
        self.log(f"A iniciar varrimento LAN em {tgt}...", "info")
        self.btn_scan.config(state="disabled")
        threading.Thread(target=self.thread_lan, args=(tgt,), daemon=True).start()

    def thread_lan(self, t):
        if HAS_NMAP_LIB and shutil.which("nmap"):
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=t, arguments='-sn')
                
                count = 0
                for h in nm.all_hosts():
                    count += 1
                    mac = nm[h]['addresses'].get('mac', 'Desconhecido')
                    vend = nm[h]['vendor'].get(mac, 'Desconhecido')
                    hostname = nm[h].hostname() if nm[h].hostname() else "N/A"
                    status = nm[h].state().upper()
                    
                    self.enqueue_ui_task(lambda h=h, m=mac, v=vend, n=hostname, s=status: 
                        self.tree_lan.insert("", 0, values=(h,m,v,n,s)))
                
                self.enqueue_ui_task(lambda: self.log(f"Varrimento concluído. {count} dispositivos localizados.", "sucesso"))
            except Exception as e:
                self.enqueue_ui_task(lambda e=e: self.log(f"Erro no Varrimento LAN: {e}", "erro"))
        else:
            self.enqueue_ui_task(lambda: self.log("Erro: Motor Nmap em falta.", "erro"))
        
        self.enqueue_ui_task(lambda: self.btn_scan.config(state="normal"))

    # --- ABA 4: DOMÍNIOS ---
    def setup_domain_tab(self):
        f = ttk.Frame(self.tab_domain); f.pack(fill="both", expand=True, padx=20, pady=20)
        ttk.Label(f, text="DOMÍNIO OU IP ALVO:", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.ent_dom = ttk.Entry(f, width=40); self.ent_dom.pack(pady=5)
        tk.Button(f, text="INVESTIGAR (WHOIS/GEOIP)", command=self.run_whois, bg="#007acc", fg="white").pack(pady=10)
        self.txt_dom = scrolledtext.ScrolledText(f, height=10); self.txt_dom.pack(fill="both", expand=True)

    def run_whois(self):
        t = self.ent_dom.get().strip()
        if not t: return
        self.txt_dom.insert(tk.END, f"A recolher inteligência sobre {t}...\n")
        threading.Thread(target=self.th_whois, args=(t,), daemon=True).start()

    def th_whois(self, t):
        try:
            import requests
            r = requests.get(f"http://ip-api.com/json/{t}?fields=status,message,country,isp,org,as,city,query", timeout=10).json()
            formatted_json = json.dumps(r, indent=2)
            self.enqueue_ui_task(lambda: self.txt_dom.insert(tk.END, formatted_json+"\n----------------\n"))
        except Exception as e:
            self.enqueue_ui_task(lambda: self.txt_dom.insert(tk.END, f"Falha na consulta remota: {e}\n"))

    # --- ABA 5: FERRAMENTAS ---
    def setup_tools_tab(self):
        f = ttk.Frame(self.tab_tools); f.pack(fill="both", expand=True, padx=20, pady=20)
        
        sec1 = ttk.LabelFrame(f, text=" Gerador Criptográfico de Senhas "); sec1.pack(fill="x", pady=5)
        ttk.Label(sec1, text="Tamanho:").pack(side="left", padx=5)
        self.ent_pass = ttk.Entry(sec1, width=5); self.ent_pass.pack(side="left"); self.ent_pass.insert(0, "16")
        tk.Button(sec1, text="Gerar", command=self.gen_pass, bg="#333333", fg="white").pack(side="left", padx=10)
        self.lbl_pass = ttk.Entry(sec1, width=30); self.lbl_pass.pack(side="left", padx=5)
        
        sec2 = ttk.LabelFrame(f, text=" Calculadora de Entropia (Força Bruta) "); sec2.pack(fill="x", pady=5)
        self.ent_crack = ttk.Entry(sec2, show="*"); self.ent_crack.pack(side="left", padx=5)
        tk.Button(sec2, text="Analisar Segurança", command=self.simular_crack, bg="#cc0000", fg="white").pack(side="left", padx=10)
        self.lbl_crack = tk.Label(sec2, text="...", bg="#1e1e1e", fg="white"); self.lbl_crack.pack(side="left")

        sec3 = ttk.LabelFrame(f, text=" Extrator de Cabeçalhos HTTP "); sec3.pack(fill="x", pady=5)
        self.ent_http_url = ttk.Entry(sec3); self.ent_http_url.pack(side="left", fill="x", expand=True, padx=5)
        tk.Button(sec3, text="Extrair", command=self.analisar_headers, bg="#007acc", fg="white").pack(side="left", padx=5)
        self.txt_http_result = scrolledtext.ScrolledText(f, height=10); self.txt_http_result.pack(fill="both", expand=True)

    def gen_pass(self):
        try: l = int(self.ent_pass.get())
        except ValueError: l=16
        c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
        self.lbl_pass.delete(0, tk.END); self.lbl_pass.insert(0, "".join(random.choice(c) for _ in range(l)))

    def format_time_human(self, seconds):
        if seconds < 1: return "Instantâneo (Vulnerável)"
        if seconds < 60: return f"{seconds:.0f} segundos"
        if seconds < 3600: return f"{seconds/60:.0f} minutos"
        if seconds < 86400: return f"{seconds/3600:.0f} horas"
        if seconds < 31536000: return f"{seconds/86400:.0f} dias"
        years = seconds / 31536000
        if years > 1000000000: return "Uma eternidade (Seguro)"
        return f"{years:.0f} anos"

    def simular_crack(self):
        s = self.ent_crack.get(); self.ent_crack.delete(0, tk.END)
        if not s: return
        pool = 0
        if re.search(r"[a-z]", s): pool += 26
        if re.search(r"[A-Z]", s): pool += 26
        if re.search(r"[0-9]", s): pool += 10
        if re.search(r"[^a-zA-Z0-9]", s): pool += 32
        if pool == 0: return
        
        entropy = math.log2(pool ** len(s))
        seconds = (pool ** len(s)) / 100_000_000_000
        
        time_str = self.format_time_human(seconds)
        color = "#ff0000" if seconds < 86400 else "#00ff00"
        self.lbl_crack.config(text=f"Tempo de quebra: {time_str} | Entropia: {entropy:.1f} bits", fg=color)

    def analisar_headers(self):
        t = self.ent_http_url.get()
        if not t: return
        if not t.startswith("http"): t = "http://" + t
        def run():
            try: 
                import requests
                r = requests.get(t, timeout=5)
                self.enqueue_ui_task(lambda: self.txt_http_result.insert(tk.END, f"URL: {t}\nStatus: {r.status_code}\nCabeçalhos:\n{json.dumps(dict(r.headers), indent=2)}\n\n"))
            except Exception as e: 
                self.enqueue_ui_task(lambda: self.txt_http_result.insert(tk.END, f"Erro de ligação: {e}\n\n"))
        threading.Thread(target=run, daemon=True).start()

    # --- ABA 6: CONFIGURAÇÕES ---
    def setup_config_tab(self):
        f = ttk.Frame(self.tab_config); f.pack(fill="both", expand=True, padx=20, pady=20)
        frm = ttk.LabelFrame(f, text=" Apresentação "); frm.pack(fill="x", pady=10)
        ttk.Label(frm, text="Esquema de Cores:").pack(side="left", padx=5)
        ttk.Combobox(frm, textvariable=self.current_theme_name, values=list(self.themes.keys()), state="readonly").pack(side="left", padx=5)
        tk.Button(frm, text="Aplicar", command=self.update_theme_colors, bg="#555555", fg="white").pack(side="left", padx=5)
        
        d = ttk.LabelFrame(f, text=" Diagnóstico do Sistema de OSINT "); d.pack(fill="both", expand=True, pady=10)
        tk.Button(d, text="Executar Verificação de Integridade", command=self.run_diag, bg="#009933", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=5)
        self.txt_diag = scrolledtext.ScrolledText(d, height=5, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.txt_diag.pack(fill="both", expand=True, padx=5, pady=5)

    def run_diag(self):
        self.txt_diag.delete('1.0', tk.END)
        self.txt_diag.insert(tk.END, "[*] A iniciar testes de diagnóstico...\n")
        self.txt_diag.insert(tk.END, f"[+] Módulo Nmap Python: {'OK' if HAS_NMAP_LIB else 'FALHA'}\n")
        self.txt_diag.insert(tk.END, f"[+] Binário Nmap no Sistema: {'OK' if bool(shutil.which('nmap')) else 'FALHA'}\n")
        self.txt_diag.insert(tk.END, f"[{'OK' if self.is_admin_check() else 'AVISO'}] Nível de Permissões: {'Administrador/Root' if self.is_admin_check() else 'Utilizador Restrito'}\n")
        try:
            import requests
            self.txt_diag.insert(tk.END, "[+] Biblioteca Requests (Web HTTP): OK\n")
        except:
             self.txt_diag.insert(tk.END, "[-] Biblioteca Requests (Web HTTP): FALHA\n")

    def update_theme_colors(self):
        t = self.themes[self.current_theme_name.get()]
        self.apply_theme(t)
        if hasattr(self, 'log_area'): self.log_area.config(bg=t["log_bg"], fg=t["log_fg"])
        if hasattr(self, 'tree'):
            for k, v in self.tree_colors.items(): self.tree.tag_configure(k, foreground=v)

    def apply_theme(self, theme):
        bg, fg, btn = theme["bg"], theme["fg"], theme["btn"]
        self.root.configure(bg=bg)
        s = ttk.Style(); s.theme_use('clam')
        s.configure("TFrame", background=bg)
        s.configure("TLabel", background=bg, foreground=fg)
        s.configure("TLabelframe", background=bg, foreground=fg)
        s.configure("TLabelframe.Label", background=bg, foreground=fg)
        s.configure("TButton", background=btn, foreground="white")
        s.configure("Treeview.Heading", background=theme.get("head_bg", "#333"), foreground=theme.get("head_fg", "white"), font=("Segoe UI", 9, "bold"))
        s.configure("Treeview", background=theme["tree_bg"], foreground=theme["tree_fg"], fieldbackground=theme["tree_bg"])

    # --- MOTOR DE CAPTURA ---
    def start_sniffing(self):
        if not self.is_admin_check():
            messagebox.showwarning("Aviso de Permissões", "Sem privilégios de Administrador/Root, o motor de captura pode falhar na interceção de pacotes.")
            
        self.sniffing_active = True
        self.behavior_active = True
        self.active_connections.clear()
        self.latest_activity.clear()
        self.stat_pkt_count.set(0)
        self.total_bytes = 0
        self.tree.delete(*self.tree.get_children())
        self.tree_behavior.delete(*self.tree_behavior.get_children())
        
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        
        threading.Thread(target=self.packet_sniffer_thread, daemon=True).start()
        threading.Thread(target=self.thread_behavior_engine, daemon=True).start()
        threading.Thread(target=self.garbage_collector, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing_active = False
        self.behavior_active = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")

    def garbage_collector(self):
        while self.sniffing_active:
            time.sleep(15)
            try:
                now = time.time()
                keys_to_remove = [k for k, v in self.active_connections.items() if v.get('last_ts', 0) < now - 120]
                
                for k in keys_to_remove:
                    self.active_connections.pop(k, None)
            except Exception as e:
                pass

    def extract_sni(self, payload: bytes) -> str:
        try:
            if len(payload) < 50 or payload[0] != 0x16 or payload[5] != 0x01: 
                return None 

            offset = 43
            
            if offset + 1 > len(payload): return None
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            if offset + 2 > len(payload): return None
            cipher_suites_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2 + cipher_suites_len
            
            if offset + 1 > len(payload): return None
            comp_methods_len = payload[offset]
            offset += 1 + comp_methods_len
            
            if offset + 2 > len(payload): return None
            extensions_len = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            
            end_extensions = offset + extensions_len
            
            while offset < end_extensions and offset + 4 <= len(payload):
                ext_type = struct.unpack('!H', payload[offset:offset+2])[0]
                ext_len = struct.unpack('!H', payload[offset+2:offset+4])[0]
                offset += 4
                
                if ext_type == 0:
                    if offset + 5 <= len(payload):
                        server_name_len = struct.unpack('!H', payload[offset+3:offset+5])[0]
                        if offset + 5 + server_name_len <= len(payload):
                            return payload[offset+5:offset+5+server_name_len].decode('utf-8')
                
                offset += ext_len
        except struct.error:
            pass
        except UnicodeDecodeError:
            pass
        return None

    def packet_sniffer_thread(self):
        s = None
        try:
            if sys.platform.startswith('linux'):
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.selected_interface.get() != "Auto / Default":
                    try: s.bind((self.selected_interface.get(), 0))
                    except OSError: pass
            else:
                local_ip = self.detect_local_ip()
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                try:
                    s.bind((local_ip, 0))
                except OSError:
                    self.enqueue_ui_task(lambda: self.log(f"Falha ao vincular no IP {local_ip}. A tentar fallback...", "erro"))
                    s.bind((socket.gethostbyname(socket.gethostname()), 0))
                    
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.enqueue_ui_task(lambda: self.log("Motor de captura iniciado e vinculado com sucesso.", "sucesso"))
            
            while self.sniffing_active:
                try:
                    s.settimeout(2.0)
                    raw, _ = s.recvfrom(65535)
                    
                    if sys.platform.startswith('linux') and not self.monitor_mode_enabled: 
                        raw = raw[14:]
                    
                    self.process_packet(raw)
                except socket.timeout:
                    continue
                except OSError:
                    pass
            
        except Exception as e: 
            self.enqueue_ui_task(lambda e=e: self.log(f"Falha Crítica no Motor de Rede: {e}", "erro"))
            self.enqueue_ui_task(self.stop_sniffing)
        finally:
            if s:
                if sys.platform == "win32" and self.sniffing_active:
                    try: s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except: pass
                s.close()
            self.enqueue_ui_task(lambda: self.log("Captura terminada.", "info"))

    def process_packet(self, raw: bytes):
        if len(raw) < 20: return
        
        # --- ATUALIZAÇÃO DE ESTATÍSTICAS ---
        self.total_bytes += len(raw)
        c = self.stat_pkt_count.get() + 1
        
        if c % 25 == 0:
            vol_str = f"{self.total_bytes/1048576:.2f} MB" if self.total_bytes > 1048576 else f"{self.total_bytes/1024:.1f} KB"
            self.enqueue_ui_task(lambda cnt=c, v=vol_str: (self.stat_pkt_count.set(cnt), self.stat_data_vol.set(v)))
        else:
            self.stat_pkt_count.set(c)

        try:
            # --- EXTRAÇÃO DE CABEÇALHO ---
            ihl = (raw[0] & 15) * 4
            proto = raw[9]
            src = socket.inet_ntoa(raw[12:16])
            dst = socket.inet_ntoa(raw[16:20])
            
            f_ip = self.filter_ip_str.get()
            if f_ip and (f_ip not in src and f_ip not in dst): return
            if src in self.active_nmap_targets or dst in self.active_nmap_targets: return

            pname = {6:"TCP", 17:"UDP", 1:"ICMP"}.get(proto, "OTHER")
            key = (src, dst, pname)
            ts = time.time()
            
            pl = b""
            if proto == 6:
                tcp_data_offset = (raw[ihl+12] >> 4) * 4
                pl = raw[ihl + tcp_data_offset:]
            elif proto == 17:
                pl = raw[ihl+8:] 
            else:
                pl = raw[ihl+20:]

            ctx = "Payload Binário / Criptografado"
            detected_domain = None
            
            # --- ANÁLISE PROFUNDA (DPI) ---
            if proto == 1:
                ctx = "Ping Remoto / Eco ICMP"
            elif len(pl) > 0:
                domain = self.extract_sni(pl)
                if domain:
                    detected_domain = domain
                    ctx = f"🔒 TLS/SNI: {domain}"
                else:
                    try:
                        txt = pl[:250].decode('utf-8', errors='ignore')
                        host_match = re.search(r'(?i)Host:\s*([a-zA-Z0-9.-]+)', txt)
                        
                        if host_match:
                            detected_domain = host_match.group(1)
                            ctx = f"🌐 HTTP Host: {detected_domain}"
                        elif "GET /" in txt or "POST /" in txt:
                            ctx = "🌐 Tráfego Web (S/ Host)"
                        
                        if re.search(r'(?i)(pass|password|login|pwd)=', txt):
                             ctx = "⚠️ ALERTA VERMELHO: Fuga de Credenciais"
                    except: pass
            
            # --- ATUALIZAÇÃO DE DADOS ---
            if key not in self.active_connections:
                self.active_connections[key] = {
                    'id': None, 'count': 0, 'history': deque(maxlen=20), 
                    'last_raw': raw, 'category': 'Outros', 'context_ui': ctx,
                    'detected_domain': detected_domain, 'last_ts': ts
                }
                if not detected_domain:
                    self.resolver_executor.submit(self.resolve_ip_sync, dst)
            
            conn = self.active_connections[key]
            conn['count'] += 1
            conn['last_raw'] = raw
            conn['last_ts'] = ts
            conn['history'].append((ts, len(raw)))
            
            if detected_domain:
                conn['detected_domain'] = detected_domain
                conn['context_ui'] = ctx 

            wc = self.filter_category.get()
            if wc == "TODOS" or wc == conn.get('category', 'Outros'):
                if not conn['id']:
                    tag = pname if pname in ["TCP", "UDP", "ICMP"] else "OTHER"
                    self.enqueue_ui_task(lambda k=key, c=conn, t=tag: self._insert_tree(k, c, t))
                elif conn['count'] % 40 == 0: 
                    self.enqueue_ui_task(lambda c=conn: self._update_tree_count(c))
        except Exception: 
            pass

    def _insert_tree(self, key, conn, tag):
        try:
            if not self.tree.exists(conn.get('id', '')):
                conn['id'] = self.tree.insert("", 0, values=(key[0], key[1], key[2], conn['context_ui'], 1, time.strftime('%H:%M:%S')), tags=(tag,))
        except Exception: pass

    def _update_tree_count(self, conn):
        try:
            if conn['id'] and self.tree.exists(conn['id']):
                self.tree.set(conn['id'], "count", conn['count'])
                self.tree.set(conn['id'], "context", conn['context_ui'])
                self.tree.set(conn['id'], "last", time.strftime('%H:%M:%S'))
        except Exception: pass

    def thread_behavior_engine(self):
        while self.behavior_active:
            time.sleep(3.0) 
            try:
                keys = list(self.active_connections.keys())
                for k in keys:
                    d = self.active_connections.get(k)
                    if not d: continue
                    hist = d['history']
                    
                    if len(hist) < 5: continue 

                    dur = hist[-1][0] - hist[0][0]
                    dur = dur if dur > 0.1 else 0.1
                    pps = len(hist) / dur
                    avg_size = sum(x[1] for x in hist) / len(hist)
                    
                    beh = "Tráfego Estável"
                    cat = "Outros"
                    risk = ThreatLevel.LOW
                    
                    if d.get('detected_domain'):
                        beh = f"Navegação: {d['detected_domain']}"
                        cat = "Web"
                        risk = ThreatLevel.SAFE
                    
                    elif "⚠️" in d['context_ui']:
                         beh, cat, risk = "Exfiltração/Credenciais Inseguras", "Security", ThreatLevel.CRITICAL
                    
                    elif k[2] == "UDP":
                        if pps > 60 and avg_size > 800: 
                            beh, cat, risk = "Consumo Elevado (Streaming)", "Media", ThreatLevel.LOW
                        elif pps > 40 and avg_size < 400: 
                            beh, cat, risk = "Comunicação (Gaming/VoIP)", "Game", ThreatLevel.LOW
                        elif pps > 200:
                            beh, cat, risk = "Anomalia: Possível UDP Flood", "Security", ThreatLevel.HIGH
                    
                    elif k[2] == "TCP":
                        if pps > 80: 
                            beh, cat, risk = "Transferência Massiva (Download)", "Web", ThreatLevel.MEDIUM
                        elif avg_size > 100 and avg_size < 1400: 
                            beh = "Sessão TCP Ativa"
                    
                    d['category'] = cat
                    
                    str_stats = f"{pps:.1f} P/s | {avg_size:.0f} b/p"
                    self.enqueue_ui_task(lambda ky=k, b=beh, st=str_stats, r=risk: self.upd_beh(ky, b, st, r))
            except Exception as e: 
                pass

    def upd_beh(self, key, beh, det, conf):
        try:
            found = False
            for child in self.tree_behavior.get_children():
                vals = self.tree_behavior.item(child)['values']
                if vals[0] == key[0] and vals[1] == key[1]:
                    self.tree_behavior.set(child, "behavior", beh)
                    self.tree_behavior.set(child, "details", det)
                    self.tree_behavior.set(child, "confidence", conf)
                    found = True
                    break
            if not found:
                 self.tree_behavior.insert("", 0, values=(key[0], key[1], key[2], beh, det, conf))
        except Exception: pass

    def resolve_ip_sync(self, ip):
        if ip in self.dns_cache: return self.dns_cache[ip]
        try: 
            h = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = h
            return h
        except socket.herror: 
            return ip

    def refresh_tree_filter(self):
        self.tree.delete(*self.tree.get_children())
        wc = self.filter_category.get()
        for k, d in self.active_connections.items():
            cc = d.get('category', 'Outros')
            if (wc=="TODOS") or (wc == cc):
                tag = k[2] if k[2] in ["TCP", "UDP", "ICMP"] else "OTHER"
                d['id'] = self.tree.insert("", 0, values=(k[0], k[1], k[2], d.get('context_ui'), d['count'], "Recente"), tags=(tag,))

    def export_sniffer_csv(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if f:
            try:
                with open(f, 'w', newline='', encoding='utf-8') as file:
                    w = csv.writer(file)
                    w.writerow(["Origem", "Destino", "Protocolo", "Contexto/Dominio", "Contagem"])
                    for i in self.tree.get_children(): w.writerow(self.tree.item(i)['values'])
                self.log("Registo CSV exportado com sucesso.", "sucesso")
                messagebox.showinfo("Sucesso", "Dados guardados com sucesso.")
            except Exception as e:
                messagebox.showerror("Erro Crítico", f"Falha na escrita: {e}")

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self.root, tearoff=0)
            val = self.tree.item(item)['values']
            menu.add_command(label=f"🔍 Analisar Origem ({val[0]})", command=lambda: self.run_nmap(val[0]))
            menu.add_command(label=f"🔍 Analisar Destino ({val[1]})", command=lambda: self.run_nmap(val[1]))
            menu.add_separator()
            menu.add_command(label="📋 Copiar IP de Origem", command=lambda: self.root.clipboard_append(val[0]))
            menu.post(event.x_root, event.y_root)

    def on_tree_double_click(self, event):
        item = self.tree.selection()
        if item:
            vals = self.tree.item(item)['values']
            for k, v in self.active_connections.items():
                if k[0] == vals[0] and k[1] == vals[1] and k[2] == vals[2]:
                     self.open_packet_window(v)
                     break

    def open_packet_window(self, conn_data):
        if 'window' in conn_data and conn_data['window'].winfo_exists():
            conn_data['window'].lift(); return

        top = tk.Toplevel(self.root); top.geometry("900x600"); top.configure(bg="#1e1e1e")
        top.title("Análise Forense de Pacote - Raw Data")
        
        t = scrolledtext.ScrolledText(top, bg="black", fg="#00ff00", font=("Consolas", 10))
        t.pack(fill="both", expand=True)
        
        raw = conn_data.get('last_raw', b'')
        analysis = self.analyze_packet_deeply_detailed(raw)
        t.insert(tk.END, analysis)
        conn_data['window'] = top

    def analyze_packet_deeply_detailed(self, raw_data):
        try:
            if len(raw_data) < 20: return "Frame descartado: Comprimento inválido."
            ver = raw_data[0] >> 4
            ttl = raw_data[8]
            proto = raw_data[9]
            src = socket.inet_ntoa(raw_data[12:16])
            dst = socket.inet_ntoa(raw_data[16:20])
            out = f"--- CAMADA DE REDE (IP) ---\nVersão: {ver}\nTempo de Vida (TTL): {ttl}\nProtocolo ID: {proto}\nOrigem: {src}\nDestino: {dst}\n"
            
            out += f"\n--- DUMP HEXADECIMAL (RAW) ---\n{binascii.hexlify(raw_data).decode('utf-8')}\n"
            return out
        except Exception as e: 
            return f"Erro na dissecção forense: {e}"

    def run_nmap(self, ip):
        if not HAS_NMAP_LIB:
            messagebox.showerror("Requisito em Falta", "A biblioteca 'python-nmap' é obrigatória para esta função.")
            return
        
        self.active_nmap_targets.add(ip); self.log(f"Iniciada a verificação de superfície de ataque em {ip}...", "info")
        threading.Thread(target=self.thread_nmap, args=(ip,), daemon=True).start()

    def thread_nmap(self, ip):
        res = ""
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments="-F -sV")
            if ip in nm.all_hosts():
                res = f"Alvo: {ip}\nEstado Atual: {nm[ip].state().upper()}\n\n"
                for proto in nm[ip].all_protocols():
                    res += f"=== Protocolo {proto.upper()} ===\n"
                    lport = nm[ip][proto].keys()
                    for port in sorted(lport):
                        s = nm[ip][proto][port]
                        res += f"  [{port}] {s['state']} | Serviço: {s['name']} (v. {s['version']})\n"
            else: res = "O anfitrião não respondeu aos testes de conectividade."
        except Exception as e: 
            res = f"Erro de processamento Nmap: {e}"
        finally:
            self.active_nmap_targets.discard(ip)
            self.enqueue_ui_task(lambda: self.show_scan_result(ip, res))

    def show_scan_result(self, ip, res):
        top = tk.Toplevel(self.root); top.geometry("600x400"); top.configure(bg="#1e1e1e")
        top.title(f"Relatório de Superfície: {ip}")
        t = scrolledtext.ScrolledText(top, bg="black", fg="#00ff00", font=("Consolas", 10))
        t.pack(fill="both", expand=True); t.insert(tk.END, res)

    def log(self, msg, tag="info"):
        self.enqueue_ui_task(lambda: self._log_impl(msg, tag))
    
    def _log_impl(self, msg, tag):
        self.log_area.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n", tag)
        self.log_area.see(tk.END)

    def get_network_interfaces(self): 
        return ["eth0", "wlan0", "Auto"]
    
    def setup_wifi_tab(self): 
        ttk.Label(self.tab_wifi, text="A captura nativa IEEE 802.11 requer adaptação específica do Kernel Linux.").pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = ScoutGUI(root)
    root.mainloop()