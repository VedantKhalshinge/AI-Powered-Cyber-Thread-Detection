"""
Packet Monitor
Captures/simulates network packets with threat flagging
"""

import time
import random
import threading
from datetime import datetime, timezone

# Try scapy; fall back to simulation
try:
    from scapy.all import sniff, IP, TCP, UDP
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444, 6667, 31337}
COMMON_SERVICES = {80: "HTTP", 443: "HTTPS", 53: "DNS", 8080: "HTTP-ALT",
                   22: "SSH", 3306: "MySQL", 5432: "PostgreSQL"}

SIMULATED_IPS = [
    "192.168.1.100", "10.0.0.55", "172.16.0.20",
    "45.33.32.156", "192.0.2.44", "203.0.113.77",
    "8.8.8.8", "1.1.1.1", "198.51.100.25",
]
KNOWN_BAD_IPS = {"45.33.32.156", "198.51.100.25"}  # Demo bad actors


def _flag_packet(src_ip, dst_ip, src_port, dst_port, size):
    flags = []
    if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
        flags.append(f"Suspicious port {dst_port or src_port}")
    if src_ip in KNOWN_BAD_IPS or dst_ip in KNOWN_BAD_IPS:
        flags.append("Known malicious IP")
    if size > 65000:
        flags.append("Oversized packet")
    return flags


class PacketMonitor:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self.running = False
        self._thread = None
        self._ip_frequency = {}

    def _simulate_packet(self):
        """Generate a realistic simulated packet."""
        src_ip = random.choice(SIMULATED_IPS)
        dst_ip = random.choice(SIMULATED_IPS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 8080, 3389, 4444, 3306, 445, 6667])
        size = random.randint(40, 1500)
        proto = random.choice(["TCP", "UDP", "ICMP"])

        flags = _flag_packet(src_ip, dst_ip, src_port, dst_port, size)
        service = COMMON_SERVICES.get(dst_port, "UNKNOWN")

        # Track IP frequency
        self._ip_frequency[src_ip] = self._ip_frequency.get(src_ip, 0) + 1
        if self._ip_frequency[src_ip] > 20:
            flags.append(f"High-frequency source IP ({self._ip_frequency[src_ip]} pkts)")

        return {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "src_port":   src_port,
            "dst_port":   dst_port,
            "protocol":   proto,
            "size":       size,
            "service":    service,
            "threat_flags": flags,
            "is_threat":  len(flags) > 0,
        }

    def _run_simulation(self):
        while self.running:
            pkt = self._simulate_packet()
            if self.socketio:
                self.socketio.emit('packet_update', pkt, namespace='/packets')
            time.sleep(random.uniform(0.3, 1.2))

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._run_simulation, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
