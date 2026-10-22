# network-defense-port-scan-simulation

A Python simulation of a **port scan attack** on a server, showing how it is detected and how a countermeasure stops it. It compares the server **before** and **after** the defense is applied.

> This is a learning project. It is a pure Python simulation and sends no real network traffic.

## What is a port scan?
A port scan is the reconnaissance step of an attack. The attacker sends a SYN packet to many ports to find which ones are open (for example 22 for SSH, 80 for HTTP, 443 for HTTPS) and uses that information to plan the next attack.

## Files
| File | Purpose |
|---|---|
| `before.py` | Vulnerable server with no protection. The attack succeeds and is only detected afterwards. |
| `after.py` | Same server with rate limiting and automatic blocking. The attacker is stopped. |

## How it works
1. **Attack:** a simulated nmap-style SYN scan probes ports 1 to 1000.
2. **Detection (IDS):** if one source IP probes 20 or more distinct ports, an alert is raised.
3. **Countermeasure (IPS):** if one IP sends more than 15 SYN packets in 1 second, it is added to a blocklist and its packets are dropped.
4. **Comparison:** `after.py` prints a before vs after table.

## How to run
Requires Python 3 (no extra libraries).

```
python before.py
python after.py
```

Run `before.py` first. It creates `before_results.json`, which `after.py` reads for the comparison.

## Expected output
**Before:** all 1000 SYN packets are answered and the open ports (22, 80, 443) are discovered. The attack is detected but not blocked.

**After:** the attacker is blocked after 15 SYN packets and the remaining packets are dropped, so the attacker discovers few or no open ports.

| Metric | Before | After |
|---|---|---|
| SYN packets answered | 1000 | 15 |
| Attacker blocked | No | Yes |
| Detection alert | Yes | Yes |

## Key concepts
- **Port scan:** probing ports to find open services
- **IDS (Intrusion Detection System):** watches traffic and raises alerts
- **IPS / rate limiting:** takes action by blocking suspicious sources
- **Threshold:** the limit that separates normal from suspicious behaviour

## Limitations
The simulation models the logic of real tools such as Wireshark, nmap and iptables, but it does not capture live network traffic.
