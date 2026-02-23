#!/usr/bin/env python3
import threading
import datetime
import time
import logging
import sqlite3
import os
from scapy.all import sniff, srp, get_if_addr, conf, ARP, Ether

# ----------------- Configuration & Logging -----------------
logging.basicConfig(filename='arp_detection.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Get the detector’s local IP so we ignore our own packets.
LOCAL_IP = get_if_addr(conf.iface)

AUTO_BLOCK = True
blocked_macs = set()

# ----------------- (Optional) Database Setup -----------------
def init_db():
    conn = sqlite3.connect('arp_data.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS arp_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        mac TEXT,
                        timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

def store_mac_in_db(ip, mac):
    conn = sqlite3.connect('arp_data.db')
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO arp_logs (ip, mac, timestamp) VALUES (?, ?, ?)",
                   (ip, mac, str(datetime.datetime.now())))
    conn.commit()
    conn.close()

# ----------------- Global ARP Mapping -----------------
IP_MAC_PAIRS = {}

# ----------------- Dummy Alert Method (Now Showing 'DANGER') -----------------
def dummy_send_alert(message):
    """
    Dummy alert function for testing that writes the alert to a file and prints it.
    The alert is printed in red with a bell icon and labeled as DANGER.
    """
    alert_message = f"{datetime.datetime.now()} - DANGER: {message}\n"
    with open("dummy_alert.log", "a") as f:
        f.write(alert_message)
    # ANSI escape sequences for red text
    red_text = "\033[91m"
    reset_text = "\033[0m"
    bell_icon = "🔔"
    # Print the alert in red with the bell icon and the word 'DANGER'
    print(f"{red_text}{bell_icon} DANGER: {message}{reset_text}")
    print("\a")  # ASCII bell (may beep on some systems)

def trigger_alarm(message):
    logging.warning("ALERT: " + message)
    print("[ALERT]", message)
    dummy_send_alert(message)

def block_attacker(attacker_mac):
    global blocked_macs
    if attacker_mac in blocked_macs:
        return  # Already blocked
    print(f"[SECURITY] Blocking attacker with MAC {attacker_mac}")
    os.system(f"iptables -A INPUT -m mac --mac-source {attacker_mac} -j DROP")
    blocked_macs.add(attacker_mac)
    logging.info(f"Auto-blocked attacker MAC: {attacker_mac}")

# ----------------- ARP Request Tracking (Optional) -----------------
class ARPRequestNode:
    def __init__(self, ip, timestamp):
        self.ip = ip
        self.timestamp = timestamp
        self.next = None

class ARPRequestList:
    def __init__(self):
        self.head = None
        self.lock = threading.Lock()

    def add_request(self, ip):
        with self.lock:
            node = ARPRequestNode(ip, datetime.datetime.now())
            node.next = self.head
            self.head = node

    def find_request(self, ip, threshold=5):
        with self.lock:
            now = datetime.datetime.now()
            cur = self.head
            while cur:
                if cur.ip == ip and (now - cur.timestamp).total_seconds() <= threshold:
                    return True
                cur = cur.next
            return False
    def cleanup(self, threshold=10):
        with self.lock:
            dummy = ARPRequestNode(None, datetime.datetime.now())
            dummy.next = self.head
            prev = dummy
            cur = self.head
            now = datetime.datetime.now()
            while cur:
                if (now - cur.timestamp).total_seconds() > threshold:
                    prev.next = cur.next
                else:
                    prev = cur
                cur = cur.next
            self.head = dummy.next

arp_request_list = ARPRequestList()

def record_request(pkt):
    target_ip = pkt[ARP].pdst
    if target_ip != LOCAL_IP:
        arp_request_list.add_request(target_ip)
        logging.info("Recorded ARP request for {}".format(target_ip))

# ----------------- Packet Processing -----------------
def is_outgoing_request(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].psrc == LOCAL_IP

def is_incoming_reply(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 2 and pkt[ARP].psrc != LOCAL_IP

def process_reply(pkt):
    # Verify consistency between Ethernet and ARP fields.
    if pkt.haslayer(Ether) and pkt[Ether].src != pkt[ARP].hwsrc:
        trigger_alarm("Inconsistent ARP headers (Ethernet src: {} != ARP hwsrc: {})".format(
            pkt[Ether].src, pkt[ARP].hwsrc))
        return

    ip_src = pkt[ARP].psrc
    mac_src = pkt[ARP].hwsrc
    ether_src = pkt[Ether].src

    if not arp_request_list.find_request(ip_src):
        logging.info("Unsolicited ARP reply: {} -> {} (Ethernet src: {})".format(
            ip_src, mac_src, ether_src))

    if ip_src in IP_MAC_PAIRS:
        if IP_MAC_PAIRS[ip_src] != mac_src:
            message = ("ARP spoof detected for IP {}: expected MAC {} but got {}. "
                       "Packet received from Ethernet src: {}.").format(
                           ip_src, IP_MAC_PAIRS[ip_src], mac_src, ether_src)
            trigger_alarm(message)
            IP_MAC_PAIRS[ip_src] = mac_src
            store_mac_in_db(ip_src, mac_src)
            if AUTO_BLOCK:
                block_attacker(ether_src)
    else:
        IP_MAC_PAIRS[ip_src] = mac_src
        store_mac_in_db(ip_src, mac_src)
        logging.info("New ARP mapping recorded: {} -> {} (Ethernet src: {})".format(
            ip_src, mac_src, ether_src))

def sniff_requests():
    sniff(filter="arp", lfilter=is_outgoing_request,
          prn=record_request, iface=conf.iface, store=False)

def sniff_replies():
    sniff(filter="arp", lfilter=is_incoming_reply,
          prn=process_reply, iface=conf.iface, store=False)

def arp_scan():
    while True:
        try:
            subnet = '.'.join(LOCAL_IP.split('.')[:-1]) + '.0/24'
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),
                         timeout=2, iface=conf.iface, verbose=False)
            for s, r in ans:
                ip_addr = r.psrc
                mac_addr = r.hwsrc
                if ip_addr == LOCAL_IP:
                    continue
                if ip_addr in IP_MAC_PAIRS and IP_MAC_PAIRS[ip_addr] != mac_addr:
                    trigger_alarm("ARP scan mismatch for IP {}: {} vs {}. (Ethernet src: {})".format(
                        ip_addr, IP_MAC_PAIRS[ip_addr], mac_addr, r.src))
                    IP_MAC_PAIRS[ip_addr] = mac_addr
                    store_mac_in_db(ip_addr, mac_addr)
                elif ip_addr not in IP_MAC_PAIRS:
                    IP_MAC_PAIRS[ip_addr] = mac_addr
                    store_mac_in_db(ip_addr, mac_addr)
                    logging.info("ARP scan new mapping: {} -> {} (Ethernet src: {})".format(
                        ip_addr, mac_addr, r.src))
        except Exception as e:
            logging.error("Error during ARP scan: " + str(e))
        time.sleep(60)

def cleanup_requests():
    while True:
        arp_request_list.cleanup(threshold=10)
        time.sleep(5)

# ----------------- MITM Detection -----------------
def detect_mitm():
    """
    Detects potential Man-In-The-Middle (MITM) attacks by checking if a single MAC address
    appears to be associated with multiple IP addresses.
    """
    while True:
        time.sleep(30)  # Check every 30 seconds
        reverse_mapping = {}
        # Build reverse mapping: MAC -> list of IPs
        for ip, mac in IP_MAC_PAIRS.items():
            reverse_mapping.setdefault(mac, []).append(ip)
        # Check for a MAC address linked to multiple IPs
        for mac, ips in reverse_mapping.items():
            if len(ips) > 1:
                message = f"Potential MITM detected: MAC {mac} is associated with multiple IPs: {ips}"
                trigger_alarm(message)
                # Optionally, auto-block the MAC address if enabled.
                if AUTO_BLOCK:
                    block_attacker(mac)

# ----------------- Main Function -----------------
def main():
    print("ARP poisoning Detector started. Monitoring ARP replies from all devices (excluding LOCAL_IP {}).".format(LOCAL_IP))
    logging.info("ARP poisoning Detector started. Monitoring ARP replies (excluding LOCAL_IP {}).".format(LOCAL_IP))

    threading.Thread(target=sniff_requests, daemon=True).start()
    threading.Thread(target=sniff_replies, daemon=True).start()
    threading.Thread(target=arp_scan, daemon=True).start()
    threading.Thread(target=cleanup_requests, daemon=True).start()
    threading.Thread(target=detect_mitm, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("ARP poisoning Detector Stopped.")
        print("Stopping ARP poisoning Detector...")

if __name__ == "__main__":
    main()
