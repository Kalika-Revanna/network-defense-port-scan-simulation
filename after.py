import random, json, os
from collections import defaultdict, deque

random.seed(1)
SERVER_OPEN_PORTS = {22, 80, 443, 3306, 8080}
ATTACKER_IP = "192.168.1.50"
THRESHOLD = 20
RATE_LIMIT = 15         # max SYNs per source per window
WINDOW = 1.0            # seconds

class ProtectedServer:
    """Same server + rate limiter + auto-blocking of scanners."""
    def __init__(self):
        self.log = []
        self.recent = defaultdict(deque)
        self.blocked = set()
        self.dropped = 0

    def receive_syn(self, src, port, t):
        self.log.append((t, src, port))
        if src in self.blocked:
            self.dropped += 1
            return "DROP"                       # no reply at all
        q = self.recent[src]
        q.append(t)
        while q and t - q[0] > WINDOW:
            q.popleft()
        if len(q) > RATE_LIMIT:                 # too many SYNs too fast
            self.blocked.add(src)
            self.dropped += 1
            return "DROP"
        return "SYN-ACK" if port in SERVER_OPEN_PORTS else "RST"

def port_scan(server, src, ports):
    t, found = 0.0, []
    ports = list(ports)
    random.shuffle(ports)
    for p in ports:
        t += 0.01
        if server.receive_syn(src, p, t) == "SYN-ACK":
            found.append(p)
    return sorted(found), t

def detect(log):
    seen = defaultdict(set)
    for _, src, port in log:
        seen[src].add(port)
    return {s: len(p) for s, p in seen.items() if len(p) >= THRESHOLD}

server = ProtectedServer()
found, duration = port_scan(server, ATTACKER_IP, range(1, 1001))
alerts = detect(server.log)

print("=== AFTER COUNTERMEASURE ===")
print("SYN packets received :", len(server.log))
print("Packets dropped      :", server.dropped)
print("Open ports discovered:", found)
print("Scan duration (sim)  : %.2f s" % duration)
print("Detection alerts     :", alerts or "none")
print("Blocked sources      :", server.blocked or "none")

# Before vs after comparison
if os.path.exists("before_results.json"):
    b = json.load(open("before_results.json"))
    print("\n=== COMPARISON ===")
    print(f"{'Metric':<22}{'Before':<12}{'After':<12}")
    print(f"{'Open ports found':<22}{len(b['ports_found']):<12}{len(found):<12}")
    print(f"{'SYNs answered':<22}{b['syn_packets']:<12}{len(server.log)-server.dropped:<12}")
    print(f"{'Attacker blocked':<22}{'No':<12}{'Yes':<12}")