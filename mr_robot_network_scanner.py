import tkinter as tk
from tkinter import scrolledtext
import scapy.all as scapy
import threading
import ipaddress
import socket
import time

class MrRobotScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Mr. Robot Network Scanner - Ethical Hacking Tool")
        self.root.geometry("800x600")
        self.root.configure(bg="#1c2526")

        # Header
        self.header = tk.Label(
            root, 
            text="fsociety Network Scanner v1.0 - Coded by Ethical Hacker",
            font=("Courier", 16, "bold"),
            fg="#00ff00",
            bg="#1c2526"
        )
        self.header.pack(pady=10)

        # IP Range Input
        self.ip_label = tk.Label(
            root, 
            text="Target IP Range (e.g., 192.168.1.0/24):",
            font=("Courier", 12),
            fg="#00ff00",
            bg="#1c2526"
        )
        self.ip_label.pack()
        self.ip_entry = tk.Entry(
            root, 
            width=30,
            font=("Courier", 12),
            bg="#0a0f0f",
            fg="#00ff00",
            insertbackground="#00ff00"
        )
        self.ip_entry.pack(pady=5)
        self.ip_entry.insert(0, "192.168.1.0/24")

        # Scan Button
        self.scan_button = tk.Button(
            root, 
            text="Initiate Scan",
            command=self.start_scan,
            font=("Courier", 12, "bold"),
            bg="#0a0f0f",
            fg="#00ff00",
            activebackground="#00ff00",
            activeforeground="#0a0f0f"
        )
        self.scan_button.pack(pady=10)

        # Output Area
        self.output = scrolledtext.ScrolledText(
            root,
            width=70,
            height=20,
            font=("Courier", 10),
            bg="#0a0f0f",
            fg="#00ff00",
            insertbackground="#00ff00",
            wrap=tk.WORD
        )
        self.output.pack(pady=10)
        self.output.insert(tk.END, "[*] Welcome to fsociety Scanner. Enter IP range and click 'Initiate Scan'.\n")
        self.output.config(state='disabled')

        # Status Label
        self.status = tk.Label(
            root,
            text="Status: Idle",
            font=("Courier", 10),
            fg="#00ff00",
            bg="#1c2526"
        )
        self.status.pack(pady=5)

    def log(self, message):
        self.output.config(state='normal')
        self.output.insert(tk.END, f"{message}\n")
        self.output.see(tk.END)
        self.output.config(state='disabled')

    def validate_ip_range(self, ip_range):
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

    def scan_network(self, ip_range):
        self.log("[*] Starting network scan...")
        self.status.config(text="Status: Scanning")
        self.scan_button.config(state='disabled')

        try:
            # Send ARP requests
            arp_request = scapy.ARP(pdst=ip_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

            self.log(f"[+] Found {len(answered_list)} devices:")
            self.log("-" * 50)

            for element in answered_list:
                ip = element[1].psrc
                mac = element[1].hwsrc
                hostname = self.get_hostname(ip)
                self.log(f"IP: {ip}\tMAC: {mac}\tHostname: {hostname}")
                time.sleep(0.1)  # Simulate real-time output

            self.log("-" * 50)
            self.log("[*] Scan completed.")

        except Exception as e:
            self.log(f"[!] Error: {str(e)}")

        self.status.config(text="Status: Idle")
        self.scan_button.config(state='normal')

    def start_scan(self):
        ip_range = self.ip_entry.get()
        if not self.validate_ip_range(ip_range):
            self.log("[!] Invalid IP range. Example: 192.168.1.0/24")
            return

        # Run scan in a separate thread to keep GUI responsive
        scan_thread = threading.Thread(target=self.scan_network, args=(ip_range,))
        scan_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = MrRobotScanner(root)
    root.mainloop()