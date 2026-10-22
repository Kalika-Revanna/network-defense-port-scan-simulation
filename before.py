import random, json
from collections import defaultdict

random.seed(1)
SERVER_OPEN_PORTS = {22, 80, 443, 3306, 8080}
ATTACKER_IP = "192.168.1.50"
THRESHOLD = 20          # distinct ports from one source = scan

class Server:
    """Vulnerable server: answers every SYN, no protection."""
    def __init__(self):
        self.log = []   # like a Wireshark capture: (time, src, dst_port)

    def receive_syn(self, src, port, t):
        self.log.append((t, src, port))
        return "SYN-ACK" if port in SERVER_OPEN_PORTS else "RST"

def port_scan(server, src, ports):
    """Simulated nmap -sS: probes ports in random order."""
    t, found = 0.0, []
    ports = list(ports)
    random.shuffle(ports)
    for p in ports:
        t += 0.01
        if server.receive_syn(src, p, t) == "SYN-ACK":
            found.append(p)
    return sorted(found), t

def detect(log):
    """IDS: flags a source that probes many distinct ports."""
    seen = defaultdict(set)
    for _, src, port in log:
        seen[src].add(port)
    return {s: len(p) for s, p in seen.items() if len(p) >= THRESHOLD}

server = Server()
found, duration = port_scan(server, ATTACKER_IP, range(1, 1001))
alerts = detect(server.log)

print("=== BEFORE COUNTERMEASURE ===")
print("SYN packets received :", len(server.log))
print("Open ports discovered:", found)
print("Scan duration (sim)  : %.2f s" % duration)
print("Detection alerts     :", alerts or "none")
print("Attack blocked?      : NO (attacker mapped all open ports)")

json.dump({"syn_packets": len(server.log), "ports_found": found,
           "duration": round(duration, 2), "blocked": False},
          open("before_results.json", "w"))