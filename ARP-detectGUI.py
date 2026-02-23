#!/usr/bin/env python3
import threading
import datetime
import time
import logging
import sqlite3
import os
import math
from scapy.all import sniff, srp, get_if_addr, conf, ARP, Ether

# For the GUI
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# ----------------- Logging & Global Variables -----------------
logging.basicConfig(filename='arp_detection.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

LOCAL_IP = get_if_addr(conf.iface)
AUTO_BLOCK = True
blocked_macs = set()
IP_MAC_PAIRS = {}  # Global mapping of IP->MAC

# Global flags for controlling the detection threads:
attack_detected = False
threat_level = 0
detection_running = False
detection_paused = False

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

# ----------------- ARP Request Tracking -----------------
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

# ----------------- ARP Packet Handlers -----------------
def is_outgoing_request(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].psrc == LOCAL_IP

def is_incoming_reply(pkt):
    return pkt.haslayer(ARP) and pkt[ARP].op == 2 and pkt[ARP].psrc != LOCAL_IP

def process_reply(pkt):
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

def dummy_send_alert(message):
    alert_message = f"{datetime.datetime.now()} - DANGER: {message}\n"
    with open("dummy_alert.log", "a") as f:
        f.write(alert_message)
    red_text = "\033[91m"
    reset_text = "\033[0m"
    bell_icon = "🔔"
    print(f"{red_text}{bell_icon} DANGER: {message}{reset_text}")
    print("\a")  # ASCII bell

def trigger_alarm(message):
    global attack_detected, threat_level
    attack_detected = True
    threat_level = min(100, threat_level + 20)
    logging.warning("ALERT: " + message)
    print("[ALERT]", message)
    dummy_send_alert(message)
def block_attacker(attacker_mac):
    global blocked_macs
    if attacker_mac in blocked_macs:
        return
    print(f"[SECURITY] Blocking attacker with MAC {attacker_mac}")
    os.system(f"iptables -A INPUT -m mac --mac-source {attacker_mac} -j DROP")
    blocked_macs.add(attacker_mac)
    logging.info(f"Auto-blocked attacker MAC: {attacker_mac}")

# ----------------- Detection Thread Loops -----------------
def sniff_requests_loop():
    global detection_running, detection_paused
    while detection_running:
        if detection_paused:
            time.sleep(0.5)
            continue
        sniff(filter="arp", lfilter=is_outgoing_request,
              prn=record_request, iface=conf.iface, store=False, timeout=1)

def sniff_replies_loop():
    global detection_running, detection_paused
    while detection_running:
        if detection_paused:
            time.sleep(0.5)
            continue
        sniff(filter="arp", lfilter=is_incoming_reply,
              prn=process_reply, iface=conf.iface, store=False, timeout=1)

def arp_scan_loop():
    global detection_running, detection_paused
    while detection_running:
        if detection_paused:
            time.sleep(0.5)
            continue
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

def cleanup_requests_loop():
    global detection_running
    while detection_running:
        arp_request_list.cleanup(threshold=10)
        time.sleep(5)

# ----------------- MITM Detection Thread -----------------
def detect_mitm_loop():
    global detection_running
    while detection_running:
        # Build reverse mapping: MAC -> list of IPs
        reverse_mapping = {}
        for ip, mac in IP_MAC_PAIRS.items():
            reverse_mapping.setdefault(mac, []).append(ip)
        # Check if any MAC address is associated with multiple IPs
        for mac, ips in reverse_mapping.items():
            if len(ips) > 1:
                trigger_alarm(f"MITM detected: MAC {mac} associated with IPs: {ips}")
        time.sleep(10)

# ----------------- Enhanced Tkinter GUI -----------------
class ArpSpoofGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP poisoning Detection Tool")
        self.root.geometry("1100x700")
        # Set the desktop icon (ensure "icon.png" exists)
        try:
            icon = tk.PhotoImage(file="icon.png")
            self.root.iconphoto(True, icon)
        except Exception as e:
            logging.warning("Icon not found: " + str(e))
        self.current_theme = "light dark"
        self.setup_styles()
        self.create_menu()
        self.create_widgets()
        self.update_threat_meter()
        self.check_attack_status()
        self.update_log_area()
        self.update_network_graph()

    def setup_styles(self):
        # Define a modern color palette for our themes.
        if self.current_theme == "dark":
            self.bg_color = "#2C2F33"
            self.fg_color = "#FFFFFF"
            self.button_bg = "#7289DA"
            self.button_fg = "#FFFFFF"
            self.accent_color = "#99AAB5"
        elif self.current_theme == "light":
            self.bg_color = "#FFFFFF"
            self.fg_color = "#333333"
            self.button_bg = "#4CAF50"
            self.button_fg = "#FFFFFF"
            self.accent_color = "#A9A9A9"
        else:  # lightblue
            self.bg_color = "#E3F2FD"
            self.fg_color = "#0D47A1"
            self.button_bg = "#64B5F6"
            self.button_fg = "#0D47A1"
            self.accent_color = "#90CAF9"

        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style(self.root)
        self.style.theme_use("clam")
        self.style.configure("TButton", font=("Segoe UI", 10), background=self.button_bg, foreground=self.button_fg)
        self.style.configure("TLabel", font=("Segoe UI", 11), background=self.bg_color, foreground=self.fg_color)
        self.style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), background=self.bg_color, foreground=self.fg_color)
        self.style.configure("TProgressbar", thickness=20)
        self.style.map("TButton", background=[("active", self.accent_color)])

    def create_menu(self):
        # Create a top menu bar for File and Settings.
        menubar = tk.Menu(self.root, bg=self.bg_color, fg=self.fg_color)
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        file_menu.add_command(label="Clear Logs", command=self.clear_logs)
        file_menu.add_command(label="View Alert Log", command=self.view_alert_log)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        settings_menu.add_command(label="Toggle Theme", command=self.toggle_theme)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)
    def create_widgets(self):
        # Header Area
        header_frame = ttk.Frame(self.root)
        header_frame.grid(row=0, column=0, columnspan=2, pady=(10, 5), padx=10, sticky="ew")
        self.heading_label = ttk.Label(header_frame, text="ARP poisoning Detection Tool", style="Header.TLabel")
        self.heading_label.pack(side="left", padx=10)
        self.detection_status_label = ttk.Label(header_frame, text="Detection Status: Stopped")
        self.detection_status_label.pack(side="right", padx=10)

        # Control Buttons
        control_frame = ttk.Frame(self.root)
        control_frame.grid(row=1, column=0, columnspan=2, pady=5, padx=10, sticky="ew")
        self.start_button = ttk.Button(control_frame, text="Start 🟢", command=self.start_detection)
        self.start_button.grid(row=0, column=0, padx=5, pady=5)
        self.stop_button = ttk.Button(control_frame, text="Stop 🔴", command=self.stop_detection)
        self.stop_button.grid(row=0, column=1, padx=5, pady=5)
        self.pause_button = ttk.Button(control_frame, text="Pause ⏸️", command=self.pause_detection)
        self.pause_button.grid(row=0, column=2, padx=5, pady=5)
        self.resume_button = ttk.Button(control_frame, text="Resume ▶️", command=self.resume_detection)
        self.resume_button.grid(row=0, column=3, padx=5, pady=5)

        # Threat Meter
        meter_frame = ttk.Frame(self.root)
        meter_frame.grid(row=2, column=0, columnspan=2, pady=5, padx=10, sticky="ew")
        self.threat_label = ttk.Label(meter_frame, text="Threat Level:")
        self.threat_label.pack(side="left", padx=5)
        self.threat_meter = ttk.Progressbar(meter_frame, orient="horizontal", length=400, mode="determinate")
        self.threat_meter.pack(side="left", padx=5)

        # Status Message
        self.status_label = ttk.Label(self.root, text="Everything looks good! ✅", foreground="green")
        self.status_label.grid(row=3, column=0, columnspan=2, pady=5)

        # Main Content Frame (Network Graph & Logs)
        content_frame = ttk.Frame(self.root)
        content_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # Left: Network Graph Canvas
        graph_frame = ttk.Frame(content_frame)
        graph_frame.grid(row=0, column=0, padx=(0, 5), sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)
        self.graph_canvas = tk.Canvas(graph_frame, bg=self.bg_color, highlightthickness=0)
        self.graph_canvas.pack(fill="both", expand=True)
        # Right: Live Log Display
        log_frame = ttk.Frame(content_frame)
        log_frame.grid(row=0, column=1, padx=(5, 0), sticky="nsew")
        content_frame.grid_columnconfigure(1, weight=1)
        self.log_display = scrolledtext.ScrolledText(log_frame, wrap="word", state="disabled",
                                                      font=("Consolas", 10), bg=self.bg_color, fg=self.fg_color)
        self.log_display.pack(fill="both", expand=True)
        # Configure tag for alert messages (red text) and others
        self.log_display.tag_configure("alert", foreground="red", font=("Consolas", 10, "bold"))
        self.log_display.tag_configure("warning", foreground="orange", font=("Consolas", 10, "bold"))
        self.log_display.tag_configure("error", foreground="red", font=("Consolas", 10, "bold"))
        self.log_display.tag_configure("info", foreground="lightgreen", font=("Consolas", 10))
        self.log_display.configure(state='normal')
        self.log_display.insert(tk.END, "Log messages will appear here...\n")
        self.log_display.configure(state='disabled')

    def show_about(self):
        about_text = (
            "ARP poisoning Detection Tool\n"
            "Version 1.0\n\n"
            "This tool monitors your network for ARP poisoning attempts and alerts you in real time.\n"
            "For detailed help, please refer to the user manual or contact support.\n\n"
            "Designed by my sonu sah"
        )
        messagebox.showinfo("About", about_text)

    def toggle_theme(self):
        # Cycle through themes: dark -> light -> lightblue -> dark...
        if self.current_theme == "dark":
            self.current_theme = "light"
        elif self.current_theme == "light":
            self.current_theme = "lightblue"
        else:
            self.current_theme = "dark"
        self.setup_styles()
        # Refresh background colors and widget styles
        self.root.configure(bg=self.bg_color)
        self.create_menu()
        self.status_label.configure(background=self.bg_color)
        self.threat_label.configure(background=self.bg_color, foreground=self.fg_color)
        self.log_display.configure(bg=self.bg_color, fg=self.fg_color)
        self.graph_canvas.configure(bg=self.bg_color)

    def start_detection(self):
        global detection_running, detection_paused
        if not detection_running:
            detection_running = True
            detection_paused = False
            threading.Thread(target=sniff_requests_loop, daemon=True).start()
            threading.Thread(target=sniff_replies_loop, daemon=True).start()
            threading.Thread(target=arp_scan_loop, daemon=True).start()
            threading.Thread(target=cleanup_requests_loop, daemon=True).start()
            # Start MITM detection thread
            threading.Thread(target=detect_mitm_loop, daemon=True).start()
            logging.info("Detection started.")
            self.detection_status_label.config(text="Detection Status: Running")
        else:
            logging.info("Detection already running.")

    def stop_detection(self):
        global detection_running
        detection_running = False
        logging.info("Detection stopped.")
        self.detection_status_label.config(text="Detection Status: Stopped")

    def pause_detection(self):
        global detection_paused, detection_running
        if not detection_running:
            messagebox.showerror("Error", "Detection is not running. Cannot pause.")
            return
        detection_paused = True
        logging.info("Detection paused.")
        self.detection_status_label.config(text="Detection Status: Paused")

    def resume_detection(self):
        global detection_paused, detection_running
        if not detection_running:
            messagebox.showerror("Error", "Detection is not running. Cannot resume.")
            return
        detection_paused = False
        logging.info("Detection resumed.")
        self.detection_status_label.config(text="Detection Status: Running")
    def clear_logs(self):
        # Clear the log display and underlying files
        self.log_display.configure(state='normal')
        self.log_display.delete("1.0", tk.END)
        self.log_display.insert(tk.END, "Logs cleared.\n")
        self.log_display.configure(state='disabled')
        try:
            with open("dummy_alert.log", "w") as f:
                f.write("")
            with open("arp_detection.log", "w") as f:
                f.write("")
            for handler in logging.getLogger().handlers:
                if hasattr(handler, 'flush'):
                    handler.flush()
        except Exception as e:
            logging.error("Error clearing log files: " + str(e))

    def view_alert_log(self):
        try:
            with open("dummy_alert.log", "r") as f:
                content = f.read().strip()
            if not content:
                content = "No alerts recorded yet."
        except Exception as e:
            content = "No alert log found."
        log_window = tk.Toplevel(self.root)
        log_window.title("Alert Log")
        log_text = scrolledtext.ScrolledText(log_window, width=80, height=20, font=("Consolas", 10))
        log_text.pack(padx=10, pady=10, fill="both", expand=True)
        log_text.insert(tk.END, content)
        log_text.configure(state='disabled')

    def update_network_graph(self):
        # Animated network graph display.
        self.graph_canvas.delete("all")
        width = self.graph_canvas.winfo_width() or 600
        height = self.graph_canvas.winfo_height() or 500
        center_x = width // 2
        center_y = height // 2

        # Animation frame for rotation/pulsation effects.
        if not hasattr(self, "animation_frame"):
            self.animation_frame = 0
        self.animation_frame += 0.05
        # Draw the local host node.
        local_radius = 20
        self.graph_canvas.create_oval(center_x - local_radius, center_y - local_radius,
                                      center_x + local_radius, center_y + local_radius,
                                      fill="#7289DA", outline="")
        self.graph_canvas.create_text(center_x, center_y, text="Local", fill="white", font=("Segoe UI", 12, "bold"))

        # Arrange other nodes in a circle.
        arrangement_radius = 0.8 * min(center_x, center_y)
        expected_prefix = '.'.join(LOCAL_IP.split('.')[:-1]) + "."
        devices = [ip for ip in IP_MAC_PAIRS.keys() if ip != LOCAL_IP and ip.startswith(expected_prefix)]
        n = len(devices)
        if n > 0:
            angle_gap = (2 * math.pi) / n
            for index, ip in enumerate(devices):
                angle = angle_gap * index + self.animation_frame
                base_other_radius = 40
                animated_radius = base_other_radius * (1 + 0.1 * math.sin(self.animation_frame * 3 + index))
                device_x = center_x + int(arrangement_radius * math.cos(angle))
                device_y = center_y + int(arrangement_radius * math.sin(angle))
                self.graph_canvas.create_oval(device_x - animated_radius, device_y - animated_radius,
                                              device_x + animated_radius, device_y + animated_radius,
                                              fill="#FF6F61", outline="")
                self.graph_canvas.create_text(device_x, device_y, text=ip,
                                              fill="black", font=("Segoe UI", 10, "bold"))
                self.graph_canvas.create_line(center_x, center_y, device_x, device_y,
                                              fill=self.accent_color, dash=(2, 2))
        self.root.after(100, self.update_network_graph)

    def update_threat_meter(self):
        global threat_level
        p = threat_level / 100.0  # p varies from 0 (good) to 1 (critical)
        # Interpolate color from yellow (#FFFF00) to red (#FF0000)
        red_val = 255
        green_val = int(255 * (1 - p))
        blue_val = 0
        progress_color = f"#{red_val:02X}{green_val:02X}{blue_val:02X}"
        self.style.configure("TProgressbar", background=progress_color, troughcolor=self.bg_color)
        self.threat_meter['value'] = threat_level
        if threat_level > 0:
            threat_level = max(0, threat_level - 1)
        self.root.after(500, self.update_threat_meter)
    def check_attack_status(self):
        global attack_detected
        if attack_detected:
            current_color = self.status_label.cget("foreground")
            new_color = "red" if current_color != "red" else "orange"
            self.status_label.config(text="🔔 ARP Spoofing Attack Detected! 🔔", foreground=new_color)
            self.root.bell()
        else:
            self.status_label.config(text="Everything looks good! ✅", foreground="green")
        attack_detected = False
        self.root.after(500, self.check_attack_status)

    def update_log_area(self):
        try:
            with open("arp_detection.log", "r") as f:
                lines = f.readlines()
            filtered_lines = [line for line in lines if ("Recorded ARP request for" not in line and
                                                          "New ARP mapping recorded:" not in line)]
            last_lines = filtered_lines[-100:]
            self.log_display.configure(state='normal')
            self.log_display.delete("1.0", tk.END)
            for line in last_lines:
                if "ALERT:" in line or "ARP spoof" in line:
                    self.log_display.insert(tk.END, line, "alert")
                elif "WARNING" in line:
                    self.log_display.insert(tk.END, line, "warning")
                elif "ERROR" in line:
                    self.log_display.insert(tk.END, line, "error")
                elif "INFO" in line:
                    self.log_display.insert(tk.END, line, "info")
                else:
                    self.log_display.insert(tk.END, line)
            self.log_display.configure(state='disabled')
        except Exception as e:
            logging.error("Error updating log area: " + str(e))
        self.root.after(2000, self.update_log_area)
def main_gui():
    root = tk.Tk()
    # Set desktop icon for detector GUI
    try:
        icon = tk.PhotoImage(file="icon.png")
        root.iconphoto(True, icon)
    except Exception as e:
        logging.warning("Icon not found: " + str(e))
    app = ArpSpoofGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main_gui()
