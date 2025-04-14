#network sniffer = tool that captures and analyzes network traffic
#it can be used to monitor network traffic, detect malicious activity, and troubleshoot network issues
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import os

packet_count = 0

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Network Sniffer")
        self.root.geometry("700x500")
        
        self.is_sniffing = False
        self.log_file = "network_traffic.log"
        self.protocol_var = tk.StringVar(value="all")

        #dropdown for protocol
        ttk.Label(root, text="Choose Protocol:").pack(pady=5)
        self.protocol_menu = ttk.Combobox(root, textvariable=self.protocol_var)
        self.protocol_menu['values'] = ("all", "tcp", "udp", "icmp")
        self.protocol_menu.pack(pady=5)

        button_frame = ttk.Frame(root)
        button_frame.pack(pady=10)

        #start Button
        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        #stop Button
        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        #close Button
        self.close_button = ttk.Button(button_frame, text="Close", command=self.close_application)
        self.close_button.pack(side=tk.LEFT, padx=5)

        #log Output
        self.output_box = tk.Text(root, height=25, width=85)
        self.output_box.pack(padx=10, pady=10)

    def log_to_file(self, message):
        """Write message to both file and GUI"""
        with open(self.log_file, 'a') as f:
            f.write(message + '\n')
        
        self.output_box.insert(tk.END, message + '\n')
        self.output_box.see(tk.END)

    def start_sniffing(self):
        self.is_sniffing = True
        protocol = self.protocol_var.get()
        start_message = f"\nStarting sniffing for {protocol.upper()}..."
        self.log_to_file(start_message)
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        thread = threading.Thread(target=self.sniff_packets, args=(protocol,))
        thread.daemon = True
        thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        stop_message = "\nStopping packet capture..."
        self.log_to_file(stop_message)
        
        # Update button states
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def close_application(self):
        # Make sure to stop sniffing before closing
        if self.is_sniffing:
            self.stop_sniffing()
        self.root.quit()
        self.root.destroy()

    def sniff_packets(self, protocol):
        filter_str = protocol if protocol != "all" else None
        sniff(filter=filter_str, prn=self.process_packet, store=False, stop_filter=lambda _: not self.is_sniffing)

    def process_packet(self, packet):
        global packet_count
        packet_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        log_lines = []

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            log_lines.append(f"[{timestamp}] IP: {src_ip} -> {dst_ip} (Packet #{packet_count})")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_lines.append(f"[{timestamp}] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            log_lines.append(f"[{timestamp}] UDP: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        if ICMP in packet:
            log_lines.append(f"[{timestamp}] ICMP: {src_ip} -> {dst_ip}")

        for line in log_lines:
            self.log_to_file(line)

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()
