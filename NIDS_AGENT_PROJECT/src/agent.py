#!/usr/bin/env python3
# Agent avec IA - Détection RÉALISTE d'attaques réseau uniquement
import socket
import json
import psutil
import time
from datetime import datetime
from collections import deque, defaultdict
import threading

SERVER_IP = "192.168.203.138"
SERVER_PORT = 5000
SECRET_KEY = "SuperSecretNIDS2025"
INTERVAL = 5

# Historique pour l'IA
cpu_history = deque(maxlen=20)
ram_history = deque(maxlen=20)
process_history = deque(maxlen=20)

# Détection d'attaques réseau
icmp_tracker = defaultdict(list)
syn_tracker = defaultdict(set)
connection_attempts = defaultdict(int)

# Stockage des attaques
detected_network_attacks = []
network_monitor_active = False

def calculate_anomaly_score(cpu, ram, processes):
    """Calcule un score d'anomalie basé sur l'historique"""
    cpu_history.append(cpu)
    ram_history.append(ram)
    process_history.append(processes)
    
    if len(cpu_history) < 10:
        return 0.0
    
    import statistics
    cpu_mean = statistics.mean(cpu_history)
    cpu_std = statistics.stdev(cpu_history) if len(cpu_history) > 1 else 0
    ram_mean = statistics.mean(ram_history)
    ram_std = statistics.stdev(ram_history) if len(ram_history) > 1 else 0
    proc_mean = statistics.mean(process_history)
    proc_std = statistics.stdev(process_history) if len(process_history) > 1 else 0
    
    cpu_z = abs((cpu - cpu_mean) / cpu_std) if cpu_std > 0 else 0
    ram_z = abs((ram - ram_mean) / ram_std) if ram_std > 0 else 0
    proc_z = abs((processes - proc_mean) / proc_std) if proc_std > 0 else 0
    
    anomaly_score = min(100, (cpu_z + ram_z + proc_z) * 10)
    return round(anomaly_score, 2)

def monitor_network_attacks():
    """Surveille le trafic réseau pour détecter les VRAIES attaques"""
    global detected_network_attacks, network_monitor_active
    network_monitor_active = True
    
    try:
        from scapy.all import sniff, IP, TCP, ICMP, UDP
        
        def packet_callback(pkt):
            global detected_network_attacks
            now = time.time()
            
            if not pkt.haslayer(IP):
                return
            
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # ===== DÉTECTION ICMP FLOOD (Ping Attack) =====
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                icmp_tracker[src_ip].append(now)
                icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if now - t < 3]
                
                # Si plus de 50 pings en 3 secondes = ATTAQUE
                if len(icmp_tracker[src_ip]) > 50:
                    detected_network_attacks.append({
                        "type": "ICMP_FLOOD",
                        "source": src_ip,
                        "destination": dst_ip,
                        "details": f"{len(icmp_tracker[src_ip])} pings/3s",
                        "severity": "CRITICAL",
                        "port": "ICMP",
                        "timestamp": datetime.now().isoformat()
                    })
                    icmp_tracker[src_ip].clear()
                    print(f"🚨 ICMP FLOOD détecté depuis {src_ip}!")
            
            # ===== DÉTECTION PORT SCAN =====
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                dst_port = pkt[TCP].dport
                syn_tracker[src_ip].add(dst_port)
                
                # Si plus de 15 ports différents = PORT SCAN
                if len(syn_tracker[src_ip]) > 15:
                    ports_list = sorted(list(syn_tracker[src_ip]))[:10]
                    detected_network_attacks.append({
                        "type": "PORT_SCAN",
                        "source": src_ip,
                        "destination": dst_ip,
                        "details": f"{len(syn_tracker[src_ip])} ports: {ports_list}...",
                        "severity": "HIGH",
                        "port": "Multiple",
                        "timestamp": datetime.now().isoformat()
                    })
                    syn_tracker[src_ip].clear()
                    print(f"🚨 PORT SCAN détecté depuis {src_ip}!")
            
            # ===== DÉTECTION SYN FLOOD =====
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                connection_attempts[src_ip] += 1
                
                # Si plus de 150 SYN = SYN FLOOD
                if connection_attempts[src_ip] > 150:
                    detected_network_attacks.append({
                        "type": "SYN_FLOOD",
                        "source": src_ip,
                        "destination": dst_ip,
                        "details": f"{connection_attempts[src_ip]} SYN packets",
                        "severity": "CRITICAL",
                        "port": pkt[TCP].dport if pkt.haslayer(TCP) else "N/A",
                        "timestamp": datetime.now().isoformat()
                    })
                    connection_attempts[src_ip] = 0
                    print(f"🚨 SYN FLOOD détecté depuis {src_ip}!")
            
            # ===== DÉTECTION XMAS SCAN =====
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags == 0x29:  # FIN + PSH + URG
                    detected_network_attacks.append({
                        "type": "XMAS_SCAN",
                        "source": src_ip,
                        "destination": dst_ip,
                        "details": "FIN+PSH+URG flags",
                        "severity": "HIGH",
                        "port": pkt[TCP].dport,
                        "timestamp": datetime.now().isoformat()
                    })
                    print(f"🚨 XMAS SCAN détecté depuis {src_ip}!")
            
            # ===== DÉTECTION NULL SCAN =====
            if pkt.haslayer(TCP) and pkt[TCP].flags == 0:
                detected_network_attacks.append({
                    "type": "NULL_SCAN",
                    "source": src_ip,
                    "destination": dst_ip,
                    "details": "TCP NULL flags",
                    "severity": "HIGH",
                    "port": pkt[TCP].dport,
                    "timestamp": datetime.now().isoformat()
                })
                print(f"🚨 NULL SCAN détecté depuis {src_ip}!")
        
        print("🔍 Surveillance réseau active...")
        sniff(prn=packet_callback, store=False, timeout=None)
        
    except ImportError:
        print("⚠️  Scapy non installé - Installez avec: sudo apt install python3-scapy")
        network_monitor_active = False
    except Exception as e:
        print(f"❌ Erreur surveillance réseau: {e}")
        network_monitor_active = False

def get_system_info():
    global detected_network_attacks
    
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    processes = len(psutil.pids())
    
    anomaly_score = calculate_anomaly_score(cpu, ram, processes)
    
    # Récupérer les attaques réseau
    network_attacks = detected_network_attacks.copy()
    detected_network_attacks.clear()
    
    is_anomaly = anomaly_score > 30
    
    return {
        "timestamp": datetime.now().isoformat(),
        "agent_name": "client-chaima",
        "cpu_percent": cpu,
        "memory_percent": ram,
        "process_count": processes,
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "open_ports": [p.laddr.port for p in psutil.net_connections() if p.status == 'LISTEN'],
        "detected_attacks": network_attacks,
        "attack_count": len(network_attacks),
        "network_monitor": "active" if network_monitor_active else "inactive"
    }

# Démarrer surveillance réseau
monitor_thread = threading.Thread(target=monitor_network_attacks, daemon=True)
monitor_thread.start()

print("🤖 Agent NIDS démarré")
print("📡 Serveur:", SERVER_IP, ":", SERVER_PORT)
print("🔍 Surveillance: ICMP Flood, Port Scan, SYN Flood, XMAS/NULL Scan")
print("")

while True:
    info = get_system_info()
    payload = {"auth": SECRET_KEY, "data": info}
    
    # Affichage seulement si attaque ou anomalie
    if info["is_anomaly"] or info["attack_count"] > 0:
        if info["is_anomaly"]:
            print(f"⚠️  ANOMALIE ! Score: {info['anomaly_score']}")
        if info["attack_count"] > 0:
            print(f"🚨 {info['attack_count']} ATTAQUE(S) RÉSEAU !")
            for attack in info["detected_attacks"]:
                print(f"   └─ {attack['type']} depuis {attack['source']} → port {attack['port']}")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((SERVER_IP, SERVER_PORT))
            s.sendall(json.dumps(payload).encode())
            if info["attack_count"] == 0:
                print(f"✅ Normal (CPU: {cpu}%, Anomalie: {anomaly_score})")
            else:
                print(f"🚨 Alerte envoyée")
    except Exception as e:
        print(f"❌ Erreur: {e}")
    
    time.sleep(INTERVAL)