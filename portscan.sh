#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortScan Pro - Scanner de ports réseau avancé
Basé sur portscan.sh de RDaneel-5090, amélioré avec les techniques de pYscan

Fonctionnalités:
- 8 types de scan (TCP Connect, SYN, UDP, NULL, FIN, Xmas, ACK, Window)
- Mode interactif et ligne de commande
- Scan parallèle pour la performance
- Export JSON/TXT
- Détection de services
- Barre de progression

Auteur original: RDaneel-5090
"""

import sys
import os
import argparse
import json
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Callable, Tuple

# Version du script
VERSION = "2.0.0"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION SCAPY (optionnel pour scans avancés)
# ═══════════════════════════════════════════════════════════════════════════════

SCAPY_AVAILABLE = False
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.sendrecv import sr, sr1
    from scapy.config import conf
    conf.verb = 0  # Mode silencieux
    SCAPY_AVAILABLE = True
except ImportError:
    pass  # Scapy non disponible, on utilisera les méthodes alternatives


# ═══════════════════════════════════════════════════════════════════════════════
# COULEURS ET AFFICHAGE
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """Codes couleur ANSI pour l'affichage terminal"""
    # Couleurs de base
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    GRAY = '\033[0;90m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Reset
    NC = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Désactive les couleurs (pour redirection fichier)"""
        for attr in dir(cls):
            if not attr.startswith('_') and attr.isupper():
                setattr(cls, attr, '')


# Icônes pour les résultats
class Icons:
    CHECK = f"{Colors.GREEN}[✓]{Colors.NC}"
    CROSS = f"{Colors.RED}[✗]{Colors.NC}"
    WARNING = f"{Colors.YELLOW}[!]{Colors.NC}"
    INFO = f"{Colors.CYAN}[i]{Colors.NC}"
    ARROW = f"{Colors.CYAN}[→]{Colors.NC}"
    SCAN = f"{Colors.MAGENTA}[~]{Colors.NC}"


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ═══════════════════════════════════════════════════════════════════════════════

# États des ports
class PortState:
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNFILTERED = "unfiltered"


# Configuration par défaut
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100
DEFAULT_RETRIES = 2

# Top 100 ports les plus courants
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111,
    123, 135, 137, 138, 139, 143, 161, 162, 389, 443,
    445, 465, 514, 515, 587, 636, 993, 995, 1080, 1099,
    1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 3000,
    3128, 3306, 3389, 4443, 4444, 5000, 5432, 5800, 5900, 5984,
    6000, 6001, 6379, 7001, 7002, 8000, 8008, 8009, 8080, 8081,
    8180, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 10443, 11211,
    27017, 27018, 28017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
    50000, 50070, 50075, 50090, 60000, 60010, 60020, 60030,
    5353, 5355, 5357, 5858, 5859, 5985, 5986, 8888, 9999, 10250
]

# Services connus (étendu)
KNOWN_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1099: "RMI",
    1433: "MSSQL",
    1434: "MSSQL-UDP",
    1521: "Oracle",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    3000: "Node.js/Grafana",
    3128: "Squid-Proxy",
    3306: "MySQL",
    3389: "RDP",
    4443: "Pharos",
    4444: "Metasploit",
    5000: "UPnP/Flask",
    5432: "PostgreSQL",
    5800: "VNC-HTTP",
    5900: "VNC",
    5984: "CouchDB",
    6000: "X11",
    6379: "Redis",
    7001: "WebLogic",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8180: "Tomcat",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Node",
    10000: "Webmin",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    50000: "SAP",
}


# ═══════════════════════════════════════════════════════════════════════════════
# FONCTIONS DE SCAN
# ═══════════════════════════════════════════════════════════════════════════════

def tcp_connect_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """
    TCP Connect Scan - Connexion complète (3-way handshake)
    
    Avantages: Fonctionne sans privilèges root, très fiable
    Inconvénients: Facilement détectable, laisse des traces dans les logs
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return PortState.OPEN
        else:
            return PortState.CLOSED
    except socket.timeout:
        return PortState.FILTERED
    except socket.error:
        return PortState.CLOSED
    except Exception:
        return PortState.FILTERED


def tcp_syn_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT, 
                 retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP SYN Scan (Half-open) - Nécessite Scapy et privilèges root
    
    Envoie SYN, attend SYN-ACK, puis RST (pas de connexion complète)
    Plus furtif que TCP Connect
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, port, timeout)
    
    for _ in range(retries):
        try:
            syn_packet = IP(dst=host) / TCP(dport=port, flags='S')
            response = sr1(syn_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None:
                        # SYN-ACK = port ouvert
                        if tcp_layer.flags in (0x12, 0x02):
                            # Envoie RST pour fermer proprement
                            sr(IP(dst=host) / TCP(dport=port, flags='R'), 
                               timeout=timeout, verbose=False)
                            return PortState.OPEN
                        # RST = port fermé
                        elif tcp_layer.flags in (0x14, 0x04):
                            return PortState.CLOSED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
        except Exception:
            pass
    
    return PortState.FILTERED


def udp_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
             retries: int = DEFAULT_RETRIES) -> str:
    """
    UDP Scan - Scan des ports UDP
    
    Plus lent que TCP car pas de handshake
    Retourne open|filtered si pas de réponse
    """
    if not SCAPY_AVAILABLE:
        # Fallback avec socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (host, port))
            try:
                sock.recvfrom(1024)
                return PortState.OPEN
            except socket.timeout:
                return PortState.OPEN_FILTERED
        except Exception:
            return PortState.CLOSED
        finally:
            sock.close()
    
    for _ in range(retries):
        try:
            udp_packet = IP(dst=host) / UDP(dport=port)
            response = sr1(udp_packet, timeout=timeout, verbose=False)
            
            if response is not None and response.haslayer(ICMP):
                icmp_layer = response.getlayer(ICMP)
                if icmp_layer is not None:
                    # Port unreachable = fermé
                    if icmp_layer.type == 3 and icmp_layer.code == 3:
                        return PortState.CLOSED
                    # Autres ICMP = filtré
                    elif icmp_layer.type == 3 and icmp_layer.code in [0, 1, 2, 9, 10, 13]:
                        return PortState.FILTERED
        except Exception:
            pass
    
    return PortState.OPEN_FILTERED


def tcp_null_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                  retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP NULL Scan - Paquet sans aucun flag
    
    Peut bypasser certains firewalls
    Nécessite Scapy
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, port, timeout)
    
    for _ in range(retries):
        try:
            null_packet = IP(dst=host) / TCP(dport=port, flags='')
            response = sr1(null_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x14:
                        return PortState.CLOSED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
            else:
                return PortState.OPEN
        except Exception:
            pass
    
    return PortState.FILTERED


def tcp_fin_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP FIN Scan - Envoie uniquement le flag FIN
    
    Furtif mais moins fiable sur Windows
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, port, timeout)
    
    for _ in range(retries):
        try:
            fin_packet = IP(dst=host) / TCP(dport=port, flags='F')
            response = sr1(fin_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x14:
                        return PortState.CLOSED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
            else:
                return PortState.OPEN
        except Exception:
            pass
    
    return PortState.FILTERED


def tcp_xmas_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                  retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP Xmas Scan - Flags FIN + PSH + URG (sapin de Noël)
    
    Très furtif mais ne fonctionne pas sur Windows
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, port, timeout)
    
    for _ in range(retries):
        try:
            xmas_packet = IP(dst=host) / TCP(dport=port, flags='FPU')
            response = sr1(xmas_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x14:
                        return PortState.CLOSED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
            else:
                return PortState.OPEN
        except Exception:
            pass
    
    return PortState.FILTERED


def tcp_ack_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                 retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP ACK Scan - Détection des règles firewall
    
    Ne détermine pas si le port est ouvert, mais si le firewall filtre
    """
    if not SCAPY_AVAILABLE:
        return PortState.FILTERED
    
    for _ in range(retries):
        try:
            ack_packet = IP(dst=host) / TCP(dport=port, flags='A')
            response = sr1(ack_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x04:
                        return PortState.UNFILTERED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
        except Exception:
            pass
    
    return PortState.FILTERED


def tcp_window_scan(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                    retries: int = DEFAULT_RETRIES) -> str:
    """
    TCP Window Scan - Analyse la taille de la fenêtre TCP
    
    Comme ACK mais examine window size pour déterminer l'état
    """
    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, port, timeout)
    
    for _ in range(retries):
        try:
            ack_packet = IP(dst=host) / TCP(dport=port, flags='A')
            response = sr1(ack_packet, timeout=timeout, verbose=False)
            
            if response is not None:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer is not None and tcp_layer.flags == 0x04:
                        if tcp_layer.window > 0:
                            return PortState.OPEN
                        else:
                            return PortState.CLOSED
                elif response.haslayer(ICMP):
                    return PortState.FILTERED
        except Exception:
            pass
    
    return PortState.FILTERED


# Dictionnaire des types de scan
SCAN_TYPES: Dict[str, Tuple[str, Callable, str, bool]] = {
    '1': ('TCP Connect', tcp_connect_scan, 'Connexion complète, fiable, détectable', False),
    '2': ('TCP SYN', tcp_syn_scan, 'Half-open, furtif, nécessite root', True),
    '3': ('UDP', udp_scan, 'Scan UDP, lent mais complet', True),
    '4': ('TCP NULL', tcp_null_scan, 'Sans flags, évade certains firewalls', True),
    '5': ('TCP FIN', tcp_fin_scan, 'Flag FIN uniquement, furtif', True),
    '6': ('TCP Xmas', tcp_xmas_scan, 'FIN+PSH+URG, très furtif', True),
    '7': ('TCP ACK', tcp_ack_scan, 'Détection règles firewall', True),
    '8': ('TCP Window', tcp_window_scan, 'Analyse fenêtre TCP', True),
}


# ═══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE DU SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class PortScanner:
    """Scanner de ports principal"""
    
    def __init__(self, host: str, ports: List[int], scan_type: str = '1',
                 timeout: float = DEFAULT_TIMEOUT, threads: int = DEFAULT_THREADS,
                 verbose: bool = False):
        self.host = host
        self.ports = ports
        self.scan_type = scan_type
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        
        # Résultats
        self.results: Dict[str, List[int]] = {
            PortState.OPEN: [],
            PortState.CLOSED: [],
            PortState.FILTERED: [],
            PortState.OPEN_FILTERED: [],
            PortState.UNFILTERED: [],
        }
        
        # Statistiques
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.scanned_count = 0
        
        # Thread lock pour les compteurs
        self._lock = threading.Lock()
        
        # Récupère la fonction de scan
        scan_info = SCAN_TYPES.get(scan_type, SCAN_TYPES['1'])
        self.scan_name = scan_info[0]
        self.scan_func = scan_info[1]
        self.requires_root = scan_info[3]
    
    def resolve_host(self) -> Optional[str]:
        """Résout le nom d'hôte en IP"""
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return None
    
    def get_service(self, port: int) -> str:
        """Retourne le nom du service pour un port"""
        return KNOWN_SERVICES.get(port, "unknown")
    
    def _scan_port(self, port: int) -> Tuple[int, str]:
        """Scanne un port unique et retourne le résultat"""
        state = self.scan_func(self.host, port, self.timeout)
        
        with self._lock:
            self.scanned_count += 1
            self.results[state].append(port)
        
        return port, state
    
    def _print_progress(self, current: int, total: int):
        """Affiche la barre de progression"""
        percent = int(current * 100 / total)
        filled = percent // 2
        bar = '█' * filled + '░' * (50 - filled)
        print(f"\r  {Colors.GRAY}[{bar}] {percent:3d}% ({current}/{total}){Colors.NC}", 
              end='', flush=True)
    
    def _print_result(self, port: int, state: str):
        """Affiche le résultat d'un port"""
        service = self.get_service(port)
        
        if state == PortState.OPEN:
            icon = Icons.CHECK
            color = Colors.GREEN
        elif state == PortState.CLOSED:
            icon = Icons.CROSS
            color = Colors.RED
        elif state in (PortState.FILTERED, PortState.OPEN_FILTERED):
            icon = Icons.WARNING
            color = Colors.YELLOW
        else:
            icon = Icons.INFO
            color = Colors.CYAN
        
        # Format aligné
        port_str = str(port).ljust(6)
        state_str = state.ljust(13)
        print(f"    {icon} {Colors.WHITE}{port_str}{Colors.NC} {color}{state_str}{Colors.NC} {Colors.GRAY}({service}){Colors.NC}")
    
    def run(self, show_closed: bool = False) -> Dict:
        """
        Lance le scan
        
        Args:
            show_closed: Affiche aussi les ports fermés
        
        Returns:
            Dictionnaire des résultats
        """
        # Résolution de l'hôte
        ip = self.resolve_host()
        if ip is None:
            print(f"  {Icons.CROSS} Impossible de résoudre: {self.host}")
            return {}
        
        # Vérifie les privilèges pour certains scans
        if self.requires_root and not SCAPY_AVAILABLE:
            print(f"  {Icons.WARNING} Scapy non disponible, fallback sur TCP Connect")
            self.scan_name = "TCP Connect (fallback)"
        
        total_ports = len(self.ports)
        
        # Affiche l'en-tête
        print()
        print(f"  {Colors.CYAN}{'═' * 60}{Colors.NC}")
        print(f"  {Colors.CYAN}║{Colors.NC}  {Colors.WHITE}SCAN EN COURS{Colors.NC}")
        print(f"  {Colors.CYAN}{'═' * 60}{Colors.NC}")
        print()
        print(f"    {Icons.ARROW} Cible:      {Colors.CYAN}{self.host}{Colors.NC} ({ip})")
        print(f"    {Icons.ARROW} Type:       {Colors.CYAN}{self.scan_name}{Colors.NC}")
        print(f"    {Icons.ARROW} Ports:      {Colors.CYAN}{total_ports}{Colors.NC}")
        print(f"    {Icons.ARROW} Threads:    {Colors.CYAN}{self.threads}{Colors.NC}")
        print(f"    {Icons.ARROW} Timeout:    {Colors.CYAN}{self.timeout}s{Colors.NC}")
        print()
        print(f"  {Colors.GRAY}{'─' * 60}{Colors.NC}")
        print()
        
        # Lance le scan
        self.start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, port): port for port in self.ports}
            
            for i, future in enumerate(as_completed(futures)):
                port, state = future.result()
                
                # Affiche la progression
                if not self.verbose and total_ports > 20:
                    self._print_progress(i + 1, total_ports)
                
                # Affiche les résultats intéressants en temps réel
                if state in (PortState.OPEN, PortState.OPEN_FILTERED, PortState.UNFILTERED):
                    if not self.verbose and total_ports > 20:
                        print()  # Nouvelle ligne après la barre de progression
                    self._print_result(port, state)
                elif self.verbose or show_closed:
                    self._print_result(port, state)
        
        self.end_time = time.time()
        
        # Efface la ligne de progression
        if not self.verbose and total_ports > 20:
            print(f"\r{' ' * 70}\r", end='')
        
        # Affiche le résumé
        self._print_summary()
        
        return self.get_results()
    
    def _print_summary(self):
        """Affiche le résumé du scan"""
        elapsed = (self.end_time or time.time()) - (self.start_time or time.time())
        
        print()
        print(f"  {Colors.GRAY}{'─' * 60}{Colors.NC}")
        print()
        print(f"  {Colors.WHITE}RÉSUMÉ{Colors.NC}")
        print()
        print(f"    Durée:           {Colors.CYAN}{elapsed:.2f}s{Colors.NC}")
        print(f"    Ports scannés:   {Colors.WHITE}{self.scanned_count}{Colors.NC}")
        print(f"    Ports ouverts:   {Colors.GREEN}{len(self.results[PortState.OPEN])}{Colors.NC}")
        print(f"    Ports filtrés:   {Colors.YELLOW}{len(self.results[PortState.FILTERED])}{Colors.NC}")
        print(f"    Open|Filtered:   {Colors.YELLOW}{len(self.results[PortState.OPEN_FILTERED])}{Colors.NC}")
        print(f"    Unfiltered:      {Colors.CYAN}{len(self.results[PortState.UNFILTERED])}{Colors.NC}")
        print(f"    Ports fermés:    {Colors.RED}{len(self.results[PortState.CLOSED])}{Colors.NC}")
        print()
        
        # Liste les ports ouverts
        if self.results[PortState.OPEN]:
            print(f"  {Colors.GREEN}Ports ouverts:{Colors.NC} {', '.join(map(str, sorted(self.results[PortState.OPEN])))}")
            print()
    
    def get_results(self) -> Dict:
        """Retourne les résultats sous forme de dictionnaire"""
        return {
            'host': self.host,
            'ip': self.resolve_host(),
            'scan_type': self.scan_name,
            'timestamp': datetime.now().isoformat(),
            'duration': (self.end_time or 0) - (self.start_time or 0),
            'total_ports': len(self.ports),
            'results': {
                'open': sorted(self.results[PortState.OPEN]),
                'closed': sorted(self.results[PortState.CLOSED]),
                'filtered': sorted(self.results[PortState.FILTERED]),
                'open_filtered': sorted(self.results[PortState.OPEN_FILTERED]),
                'unfiltered': sorted(self.results[PortState.UNFILTERED]),
            },
            'services': {
                port: self.get_service(port) 
                for port in self.results[PortState.OPEN]
            }
        }
    
    def export_json(self, filename: str):
        """Exporte les résultats en JSON"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.get_results(), f, indent=2, ensure_ascii=False)
        print(f"  {Icons.CHECK} Résultats exportés: {Colors.CYAN}{filename}{Colors.NC}")
    
    def export_txt(self, filename: str):
        """Exporte les résultats en texte"""
        results = self.get_results()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Port Scan Results\n")
            f.write(f"# Host: {results['host']} ({results['ip']})\n")
            f.write(f"# Scan type: {results['scan_type']}\n")
            f.write(f"# Date: {results['timestamp']}\n")
            f.write(f"# Duration: {results['duration']:.2f}s\n")
            f.write(f"#\n")
            f.write(f"# PORT\tSTATE\tSERVICE\n")
            
            for port in results['results']['open']:
                service = results['services'].get(port, 'unknown')
                f.write(f"{port}\topen\t{service}\n")
            
            for port in results['results']['filtered']:
                f.write(f"{port}\tfiltered\t-\n")
            
            for port in results['results']['open_filtered']:
                f.write(f"{port}\topen|filtered\t-\n")
        
        print(f"  {Icons.CHECK} Résultats exportés: {Colors.CYAN}{filename}{Colors.NC}")


# ═══════════════════════════════════════════════════════════════════════════════
# MODE INTERACTIF
# ═══════════════════════════════════════════════════════════════════════════════

def show_banner():
    """Affiche la bannière du programme"""
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    
    print(f"{Colors.CYAN}")
    print(r"  ╔═══════════════════════════════════════════════════════════════╗")
    print(r"  ║                                                               ║")
    print(r"  ║   ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗   ║")
    print(r"  ║   ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗  ║")
    print(r"  ║   ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║  ║")
    print(r"  ║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║  ║")
    print(r"  ║   ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║  ║")
    print(r"  ║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝  ║")
    print(r"  ║                                                               ║")
    print(f"  ║              {Colors.WHITE}Professional Port Scanner v{VERSION}{Colors.CYAN}               ║")
    print(r"  ║                                                               ║")
    print(r"  ╚═══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}")
    print(f"  {Colors.GRAY}Basé sur portscan.sh de RDaneel-5090{Colors.NC}")
    print()


def show_menu():
    """Affiche le menu principal"""
    show_banner()
    
    print(f"  {Colors.WHITE}Commandes disponibles:{Colors.NC}")
    print()
    print(f"    {Colors.CYAN}scan{Colors.NC}     - Scan personnalisé (choix des ports et type)")
    print(f"    {Colors.CYAN}quick{Colors.NC}    - Scan rapide (top 100 ports)")
    print(f"    {Colors.CYAN}full{Colors.NC}     - Scan complet (tous les 65535 ports)")
    print(f"    {Colors.CYAN}common{Colors.NC}   - Scan des ports web courants")
    print(f"    {Colors.CYAN}help{Colors.NC}     - Aide sur les types de scan")
    print(f"    {Colors.CYAN}clear{Colors.NC}    - Effacer l'écran")
    print(f"    {Colors.CYAN}exit{Colors.NC}     - Quitter")
    print()
    
    if SCAPY_AVAILABLE:
        print(f"  {Icons.CHECK} Scapy disponible - Tous les scans activés")
    else:
        print(f"  {Icons.WARNING} Scapy non installé - Seul TCP Connect disponible")
        print(f"  {Colors.GRAY}    Installez avec: pip install scapy{Colors.NC}")
    print()


def show_help():
    """Affiche l'aide sur les types de scan"""
    print()
    print(f"  {Colors.WHITE}Types de scan disponibles:{Colors.NC}")
    print()
    
    for key, (name, _, desc, needs_root) in SCAN_TYPES.items():
        root_indicator = f"{Colors.YELLOW}*{Colors.NC}" if needs_root else " "
        available = "✓" if not needs_root or SCAPY_AVAILABLE else "✗"
        print(f"    {Colors.CYAN}{key}.{Colors.NC} {name.ljust(12)} {root_indicator} [{available}] {Colors.GRAY}{desc}{Colors.NC}")
    
    print()
    print(f"  {Colors.YELLOW}*{Colors.NC} = Nécessite Scapy et/ou privilèges root")
    print()


def parse_ports(port_input: str) -> List[int]:
    """Parse l'entrée utilisateur pour les ports"""
    ports = []
    
    if port_input == '*' or port_input.lower() == 'all':
        return list(range(1, 65536))
    
    if port_input.lower() == 'top' or port_input.lower() == 'common':
        return TOP_PORTS.copy()
    
    # Gère les plages et listes
    for part in port_input.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, min(end + 1, 65536)))
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                pass
    
    return sorted(set(ports))


def interactive_scan():
    """Mode scan interactif"""
    print()
    
    # Demande la cible
    target = input(f"  {Colors.CYAN}Cible (IP/hostname):{Colors.NC} ").strip()
    if not target:
        print(f"  {Icons.CROSS} Aucune cible spécifiée")
        return
    
    # Demande les ports
    print()
    print(f"  {Colors.WHITE}Options de ports:{Colors.NC}")
    print(f"    {Colors.GRAY}Port unique:{Colors.NC}    80")
    print(f"    {Colors.GRAY}Liste:{Colors.NC}          22,80,443,8080")
    print(f"    {Colors.GRAY}Plage:{Colors.NC}          1-1000")
    print(f"    {Colors.GRAY}Top 100:{Colors.NC}        top")
    print(f"    {Colors.GRAY}Tous:{Colors.NC}           *")
    print()
    
    port_input = input(f"  {Colors.CYAN}Ports:{Colors.NC} ").strip()
    if not port_input:
        print(f"  {Icons.CROSS} Aucun port spécifié")
        return
    
    ports = parse_ports(port_input)
    if not ports:
        print(f"  {Icons.CROSS} Format de ports invalide")
        return
    
    # Demande le type de scan
    print()
    print(f"  {Colors.WHITE}Types de scan:{Colors.NC}")
    for key, (name, _, desc, _) in SCAN_TYPES.items():
        print(f"    {Colors.CYAN}{key}.{Colors.NC} {name} - {Colors.GRAY}{desc}{Colors.NC}")
    print()
    
    scan_type = input(f"  {Colors.CYAN}Type de scan [1]:{Colors.NC} ").strip() or '1'
    if scan_type not in SCAN_TYPES:
        print(f"  {Icons.CROSS} Type de scan invalide")
        return
    
    # Options avancées
    print()
    threads = input(f"  {Colors.CYAN}Threads [{DEFAULT_THREADS}]:{Colors.NC} ").strip()
    threads = int(threads) if threads.isdigit() else DEFAULT_THREADS
    
    timeout = input(f"  {Colors.CYAN}Timeout [{DEFAULT_TIMEOUT}s]:{Colors.NC} ").strip()
    try:
        timeout = float(timeout) if timeout else DEFAULT_TIMEOUT
    except ValueError:
        timeout = DEFAULT_TIMEOUT
    
    # Demande l'export
    print()
    output = input(f"  {Colors.CYAN}Fichier de sortie (vide pour aucun):{Colors.NC} ").strip()
    
    # Lance le scan
    scanner = PortScanner(
        host=target,
        ports=ports,
        scan_type=scan_type,
        timeout=timeout,
        threads=threads
    )
    
    scanner.run()
    
    # Export si demandé
    if output:
        if output.endswith('.json'):
            scanner.export_json(output)
        else:
            scanner.export_txt(output if output.endswith('.txt') else output + '.txt')


def quick_scan():
    """Scan rapide des 100 ports les plus courants"""
    print()
    target = input(f"  {Colors.CYAN}Cible (IP/hostname):{Colors.NC} ").strip()
    if not target:
        print(f"  {Icons.CROSS} Aucune cible spécifiée")
        return
    
    scanner = PortScanner(
        host=target,
        ports=TOP_PORTS,
        scan_type='1',
        threads=DEFAULT_THREADS
    )
    scanner.run()


def full_scan():
    """Scan complet de tous les ports"""
    print()
    target = input(f"  {Colors.CYAN}Cible (IP/hostname):{Colors.NC} ").strip()
    if not target:
        print(f"  {Icons.CROSS} Aucune cible spécifiée")
        return
    
    print()
    print(f"  {Icons.WARNING} Ceci va scanner les 65535 ports. Cela peut prendre du temps.")
    confirm = input(f"  {Colors.CYAN}Continuer? [y/N]:{Colors.NC} ").strip().lower()
    
    if confirm != 'y':
        print(f"  {Icons.CROSS} Scan annulé")
        return
    
    scanner = PortScanner(
        host=target,
        ports=list(range(1, 65536)),
        scan_type='2' if SCAPY_AVAILABLE else '1',
        threads=200  # Plus de threads pour le full scan
    )
    scanner.run()


def common_scan():
    """Scan des ports web courants"""
    print()
    target = input(f"  {Colors.CYAN}Cible (IP/hostname):{Colors.NC} ").strip()
    if not target:
        print(f"  {Icons.CROSS} Aucune cible spécifiée")
        return
    
    # Ports web courants
    web_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000]
    
    scanner = PortScanner(
        host=target,
        ports=web_ports,
        scan_type='1',
        threads=20
    )
    scanner.run()


def interactive_mode():
    """Boucle principale du mode interactif"""
    show_menu()
    
    while True:
        try:
            cmd = input(f"{Colors.CYAN}portscan{Colors.NC} {Colors.WHITE}>{Colors.NC} ").strip().lower()
            
            if cmd in ('scan', 's'):
                interactive_scan()
            elif cmd in ('quick', 'q'):
                quick_scan()
            elif cmd in ('full', 'f'):
                full_scan()
            elif cmd in ('common', 'web', 'w'):
                common_scan()
            elif cmd in ('help', 'h', '?'):
                show_help()
            elif cmd in ('clear', 'cls', 'c'):
                show_menu()
            elif cmd in ('exit', 'quit', 'x'):
                print()
                print(f"  {Colors.CYAN}Au revoir!{Colors.NC}")
                print()
                sys.exit(0)
            elif cmd == '':
                pass
            else:
                print(f"  {Icons.CROSS} Commande inconnue: {cmd}")
                print(f"  {Icons.INFO} Tapez 'help' pour voir les commandes disponibles")
                print()
        
        except KeyboardInterrupt:
            print()
            print()
            print(f"  {Colors.CYAN}Au revoir!{Colors.NC}")
            print()
            sys.exit(0)
        
        except Exception as e:
            print(f"  {Icons.CROSS} Erreur: {e}")
            print()


# ═══════════════════════════════════════════════════════════════════════════════
# MODE LIGNE DE COMMANDE
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse les arguments de la ligne de commande"""
    parser = argparse.ArgumentParser(
        description='PortScan Pro - Scanner de ports réseau avancé',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  %(prog)s -H 192.168.1.1 -p 22,80,443
  %(prog)s -H example.com -r 1-1000
  %(prog)s -H 10.0.0.1 -p top -t 2 -o results.json
  %(prog)s --interactive
        """
    )
    
    parser.add_argument('-H', '--host', metavar='HOST',
                        help='Hôte cible (IP ou nom de domaine)')
    parser.add_argument('-p', '--ports', metavar='PORTS',
                        help='Ports à scanner (ex: 22,80,443 ou top ou *)')
    parser.add_argument('-r', '--range', metavar='START-END',
                        help='Plage de ports (ex: 1-1000)')
    parser.add_argument('-s', '--scan-type', metavar='TYPE', default='1',
                        choices=['1', '2', '3', '4', '5', '6', '7', '8'],
                        help='Type de scan (1-8, défaut: 1)')
    parser.add_argument('-t', '--timeout', metavar='SEC', type=float,
                        default=DEFAULT_TIMEOUT,
                        help=f'Timeout par port (défaut: {DEFAULT_TIMEOUT}s)')
    parser.add_argument('-T', '--threads', metavar='NUM', type=int,
                        default=DEFAULT_THREADS,
                        help=f'Nombre de threads (défaut: {DEFAULT_THREADS})')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Fichier de sortie (.txt ou .json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Mode verbeux')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Mode interactif')
    parser.add_argument('-V', '--version', action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('--no-color', action='store_true',
                        help='Désactiver les couleurs')
    
    return parser.parse_args()


def main():
    """Point d'entrée principal"""
    args = parse_args()
    
    # Désactive les couleurs si demandé
    if args.no_color:
        Colors.disable()
    
    # Mode interactif
    if args.interactive or (not args.host and not args.ports and not args.range):
        interactive_mode()
        return
    
    # Mode ligne de commande
    if not args.host:
        print(f"{Icons.CROSS} L'hôte cible est requis. Utilisez -H <host>")
        sys.exit(1)
    
    # Parse les ports
    if args.range:
        try:
            start, end = map(int, args.range.split('-'))
            ports = list(range(start, end + 1))
        except ValueError:
            print(f"{Icons.CROSS} Format de plage invalide: {args.range}")
            sys.exit(1)
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        print(f"{Icons.CROSS} Spécifiez des ports avec -p ou une plage avec -r")
        sys.exit(1)
    
    if not ports:
        print(f"{Icons.CROSS} Aucun port valide spécifié")
        sys.exit(1)
    
    # Affiche le banner
    show_banner()
    
    # Lance le scan
    scanner = PortScanner(
        host=args.host,
        ports=ports,
        scan_type=args.scan_type,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )
    
    scanner.run(show_closed=args.verbose)
    
    # Export si demandé
    if args.output:
        if args.output.endswith('.json'):
            scanner.export_json(args.output)
        else:
            scanner.export_txt(args.output)
    
    # Code de retour
    if scanner.results[PortState.OPEN]:
        sys.exit(0)
    else:
        sys.exit(2)


if __name__ == '__main__':
    main()
