import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
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
import ctypes
import queue
import concurrent.futures
import winsound 

# --- IMPORTAÇÕES OPCIONAIS ---
try:
    import requests
except ImportError:
    pass

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


class ScoutSentinel:
    def __init__(self, root):
        self.root = root
        self.root.title("Scout Sentinel v3.5 Pro - Host Intrusion Monitor")
        self.root.geometry("1200x800")
        
        # --- FILA DE EVENTOS GUI ---
        self.ui_queue = queue.Queue()
        self.process_ui_queue()
        
        # --- SETUP INICIAL ---
        self.ensure_admin_rights()
        self.local_ip = self.detect_local_ip()
        
        # --- VARIÁVEIS DE ESTADO ---
        self.sniffing_active = False
        self.sentinel_mode = tk.BooleanVar(value=True)
        
        self.stat_pkt_count = tk.IntVar(value=0)
        self.stat_risk_level = tk.StringVar(value="SEGURO")
        
        # --- ESTRUTURAS DE DADOS ---
        self.active_connections = {} 
        self.dns_cache = {}
        
        self.resolver_executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
        
        # --- INICIALIZAÇÃO DA INTERFACE ---
        self.build_ui()
        self.root.after(1000, self.check_dependencies)

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
        except Exception: 
            pass

    def detect_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception: 
            return "127.0.0.1"

    def build_ui(self):
        # --- ESTILOS ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Risk.TLabel", font=("Segoe UI", 16, "bold"))
        
        # --- CABEÇALHO / STATUS ---
        self.top_frame = tk.Frame(self.root, bg="#1e1e1e", height=80)
        self.top_frame.pack(fill="x")
        
        self.lbl_title = tk.Label(self.top_frame, text=f"SENTINELA ATIVO: {self.local_ip}", font=("Consolas", 14, "bold"), bg="#1e1e1e", fg="#00ff00")
        self.lbl_title.pack(pady=(15, 5))
        
        self.lbl_risk = tk.Label(self.top_frame, textvariable=self.stat_risk_level, font=("Segoe UI", 12), bg="#1e1e1e", fg="#00ff00")
        self.lbl_risk.pack(pady=0)

        # --- CONTROLOS ---
        ctrl_frame = ttk.Frame(self.root)
        ctrl_frame.pack(fill="x", padx=10, pady=10)
        
        self.btn_start = ttk.Button(ctrl_frame, text="🛡️ INICIAR PROTEÇÃO", command=self.start_sentinel)
        self.btn_start.pack(side="left", padx=5)
        
        self.btn_stop = ttk.Button(ctrl_frame, text="⏹ PARAR", command=self.stop_sentinel, state="disabled")
        self.btn_stop.pack(side="left", padx=5)
        
        ttk.Checkbutton(ctrl_frame, text="Modo Silencioso (Sem Popups)", variable=self.sentinel_mode).pack(side="right")

        # --- ÁREA PRINCIPAL ---
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill="both", expand=True, padx=10, pady=5)
        
        # --- LISTA DE CONEXÕES ATIVAS ---
        frame_list = ttk.LabelFrame(paned, text=" Conexões Ativas da Minha Máquina ")
        paned.add(frame_list, weight=2)
        
        cols = ("remote", "proto", "info", "risk", "up", "down")
        self.tree = ttk.Treeview(frame_list, columns=cols, show="headings", height=12)
        self.tree.heading("remote", text="Remoto (IP/Domínio)"); self.tree.column("remote", width=200)
        self.tree.heading("proto", text="Proto"); self.tree.column("proto", width=60, anchor="center")
        self.tree.heading("info", text="Contexto / Processo"); self.tree.column("info", width=350)
        self.tree.heading("risk", text="Nível de Risco"); self.tree.column("risk", width=120, anchor="center")
        self.tree.heading("up", text="Upload"); self.tree.column("up", width=80, anchor="e")
        self.tree.heading("down", text="Download"); self.tree.column("down", width=80, anchor="e")
        
        # --- CORES E NÍVEIS DE RISCO ---
        self.tree.tag_configure("risk_critical", background="#8b0000", foreground="white")
        self.tree.tag_configure("risk_high", background="#cc5500", foreground="white")
        self.tree.tag_configure("risk_medium", background="#aaaa00", foreground="black")
        self.tree.tag_configure("risk_low", background="#003300", foreground="white")
        self.tree.tag_configure("risk_safe", background="#ffffff", foreground="black")
        
        sb = ttk.Scrollbar(frame_list, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # --- REGISTO DE ALERTAS ---
        frame_log = ttk.LabelFrame(paned, text=" ⚠️ Histórico de Alertas de Segurança ")
        paned.add(frame_log, weight=1)
        
        self.log_area = scrolledtext.ScrolledText(frame_log, height=6, font=("Consolas", 10), bg="black", fg="#ff5555")
        self.log_area.pack(fill="both", expand=True)

    def check_dependencies(self):
        if not HAS_NMAP_LIB:
            self.enqueue_ui_task(lambda: self.log_alert("Sistema", "Módulo Nmap não detetado. Algumas funções avançadas estão desativadas.", "AVISO"))

    # --- MOTOR SENTINELA ---
    def start_sentinel(self):
        self.sniffing_active = True
        self.active_connections.clear()
        self.tree.delete(*self.tree.get_children())
        self.stat_risk_level.set("MONITORIZAÇÃO ATIVA - SEGURO")
        self.top_frame.config(bg="#1e1e1e")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        
        threading.Thread(target=self.packet_sniffer, daemon=True).start()
        threading.Thread(target=self.threat_analyzer, daemon=True).start()
        threading.Thread(target=self.garbage_collector, daemon=True).start()
        
        self.enqueue_ui_task(lambda: self.log_alert("SISTEMA", "Motor Sentinela de intrusão iniciado com sucesso.", "INFO"))

    def stop_sentinel(self):
        self.sniffing_active = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.stat_risk_level.set("SISTEMA PAUSADO")
        self.enqueue_ui_task(lambda: self.log_alert("SISTEMA", "Monitorização interrompida pelo utilizador.", "INFO"))

    def garbage_collector(self):
        while self.sniffing_active:
            time.sleep(30)
            try:
                now = time.time()
                keys_to_remove = [k for k, v in self.active_connections.items() if v.get('last_ts', 0) < now - 300]
                
                for k in keys_to_remove:
                    self.active_connections.pop(k, None)
            except Exception:
                pass

    def packet_sniffer(self):
        s = None
        try:
            if sys.platform == "win32":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((self.local_ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

            while self.sniffing_active:
                try:
                    s.settimeout(2.0)
                    raw, _ = s.recvfrom(65535)
                    if sys.platform.startswith('linux'): 
                        raw = raw[14:]
                    self.process_packet(raw)
                except socket.timeout:
                    continue
                except OSError:
                    pass
                
        except Exception as e:
            self.enqueue_ui_task(lambda err=e: self.log_alert("SISTEMA", f"Erro Crítico no Sniffer: {err}", "CRÍTICO"))
            self.enqueue_ui_task(self.stop_sentinel)
        finally:
            if s:
                if sys.platform == "win32" and self.sniffing_active:
                    try: s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception: pass
                s.close()

    def process_packet(self, raw: bytes):
        if len(raw) < 20: return
        
        try:
            ihl = (raw[0] & 15) * 4
            src = socket.inet_ntoa(raw[12:16])
            dst = socket.inet_ntoa(raw[16:20])
            
            # --- FILTRO RÍGIDO (HOST LOCAL) ---
            direction = None
            remote_ip = None
            
            if src == self.local_ip:
                direction = "OUT"
                remote_ip = dst
            elif dst == self.local_ip:
                direction = "IN"
                remote_ip = src
            else:
                return 

            proto = raw[9]
            pname = {6:"TCP", 17:"UDP", 1:"ICMP"}.get(proto, "RAW")
            payload_len = len(raw)
            
            payload = b""
            ctx = ""
            domain = None
            
            # --- EXTRAÇÃO DE DADOS ---
            if proto == 6: 
                tcp_offset = ihl + ((raw[ihl+12] >> 4) * 4)
                payload = raw[tcp_offset:]
            elif proto == 17: 
                payload = raw[ihl+8:]
            
            # --- ANÁLISE DE CONTEÚDO ---
            if len(payload) > 0:
                domain = self.extract_sni(payload)
                if not domain:
                    try:
                        txt = payload[:250].decode('utf-8', errors='ignore')
                        m = re.search(r'(?i)Host:\s*([a-zA-Z0-9.-]+)', txt)
                        if m: 
                            domain = m.group(1)
                        if re.search(r'(?i)(pass|password|login|pwd)=', txt):
                            ctx = "⚠️ ALERTA: CREDENCIAIS EM TEXTO CLARO"
                    except Exception: pass
            
            if domain: 
                ctx = f"Site: {domain} {ctx}".strip()
            elif not ctx: 
                ctx = "Tráfego Criptografado/Binário"

            # --- ATUALIZAÇÃO DE ESTRUTURAS ---
            key = (remote_ip, pname)
            if key not in self.active_connections:
                self.active_connections[key] = {
                    'id': None, 'remote': remote_ip, 'proto': pname, 
                    'info': ctx, 'risk': ThreatLevel.SAFE, 
                    'up': 0, 'down': 0, 'last_ts': time.time(),
                    'domain': domain, 'alerted': False
                }
                if not domain: 
                    self.resolver_executor.submit(self.resolve_dns, remote_ip)

            conn = self.active_connections[key]
            conn['last_ts'] = time.time()
            if domain and not conn['domain']: 
                conn['domain'] = domain
            
            if direction == "OUT": conn['up'] += payload_len
            else: conn['down'] += payload_len
            
            if "⚠️" in ctx: conn['info'] = ctx

            # --- ATUALIZAÇÃO DA INTERFACE ---
            if random.random() < 0.1: 
                 safe_conn_copy = conn.copy()
                 self.enqueue_ui_task(lambda k=key, c=safe_conn_copy: self.update_tree(k, c))
                 
        except Exception:
            pass 

    def update_tree(self, key, conn):
        try:
            disp_remote = conn['domain'] if conn['domain'] else conn['remote']
            vals = (disp_remote, conn['proto'], conn['info'], conn['risk'], 
                    f"{conn['up']/1024:.1f} KB", f"{conn['down']/1024:.1f} KB")
            
            tag = "risk_safe"
            if conn['risk'] == ThreatLevel.CRITICAL: tag = "risk_critical"
            elif conn['risk'] == ThreatLevel.HIGH: tag = "risk_high"
            elif conn['risk'] == ThreatLevel.MEDIUM: tag = "risk_medium"
            elif conn['risk'] == ThreatLevel.LOW: tag = "risk_low"

            if conn['id'] is None or not self.tree.exists(conn['id']):
                new_id = self.tree.insert("", 0, values=vals, tags=(tag,))
                if key in self.active_connections:
                    self.active_connections[key]['id'] = new_id
            else:
                self.tree.item(conn['id'], values=vals, tags=(tag,))
        except Exception:
            pass

    # --- MOTOR DE ANÁLISE DE AMEAÇAS ---
    def threat_analyzer(self):
        while self.sniffing_active:
            time.sleep(2)
            try:
                for key, conn in self.active_connections.items():
                    if conn.get('alerted', False): continue 
                    
                    current_risk = ThreatLevel.SAFE
                    reason = ""
                    remote_ip = conn['remote']
                    
                    is_private = (remote_ip.startswith("192.168.") or remote_ip.startswith("10.") or 
                                  remote_ip.startswith("127.") or remote_ip.startswith("224.") or 
                                  remote_ip.endswith(".255"))
                    
                    if not is_private:
                        # --- ANÁLISE DE EXFILTRAÇÃO ---
                        if conn['up'] > 5 * 1024 * 1024: 
                            if conn['up'] > conn['down'] * 5: 
                                current_risk = ThreatLevel.HIGH
                                reason = "POSSÍVEL EXFILTRAÇÃO (Upload Massivo Detetado)"

                        # --- DETEÇÃO DE CREDENCIAIS ---
                        if conn['proto'] == "TCP" and "⚠️" in conn['info']:
                            current_risk = ThreatLevel.CRITICAL
                            reason = "FUGA DE INFORMAÇÃO (Credencial/Senha não encriptada)"

                    if current_risk in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                        conn['risk'] = current_risk
                        conn['alerted'] = True 
                        
                        target_disp = conn.get('domain') or remote_ip
                        alert_msg = f"{current_risk.upper()}: {reason} -> {target_disp}"
                        self.enqueue_ui_task(lambda m=alert_msg: self.trigger_alarm(m))
                    else:
                        conn['risk'] = ThreatLevel.SAFE
                        
            except RuntimeError:
                pass 

    # --- SISTEMA DE ALARMES ---
    def trigger_alarm(self, message):
        self.log_alert("SENTINELA", message, "ALERTA")
        
        self.lbl_title.config(fg="red", text="⚠️ AMEAÇA DETETADA ⚠️")
        self.top_frame.config(bg="#330000")
        self.stat_risk_level.set(message)
        
        self.root.deiconify()
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after(1500, lambda: self.root.attributes('-topmost', False))
        
        if sys.platform == "win32" and not self.sentinel_mode.get():
            try: winsound.Beep(1200, 600) 
            except Exception: pass

    def log_alert(self, source, msg, level):
        ts = time.strftime('%H:%M:%S')
        self.log_area.insert(tk.END, f"[{ts}] [{level}] {msg}\n")
        self.log_area.see(tk.END)

    # --- RESOLUÇÃO DNS E SNI ---
    def resolve_dns(self, ip):
        if ip in self.dns_cache: return self.dns_cache[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = name
            
            for k, v in self.active_connections.items():
                if v.get('remote') == ip and not v.get('domain'):
                    v['domain'] = name
            return name
        except Exception: 
            return None

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
            
            end_ext = offset + extensions_len
            while offset < end_ext and offset + 4 <= len(payload):
                etype = struct.unpack('!H', payload[offset:offset+2])[0]
                elen = struct.unpack('!H', payload[offset+2:offset+4])[0]
                offset += 4
                
                if etype == 0:
                    if offset + 2 <= len(payload):
                        slen = struct.unpack('!H', payload[offset+3:offset+5])[0]
                        if offset + 5 + slen <= len(payload):
                            return payload[offset+5:offset+5+slen].decode('utf-8')
                offset += elen
        except Exception: 
            pass
        return None

if __name__ == "__main__":
    root = tk.Tk()
    app = ScoutSentinel(root)
    root.mainloop()