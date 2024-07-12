from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext, messagebox
import binascii
import threading

# Global variable to control packet sniffing
sniffing = False

def packet_analysis(packet):
    global sniffing
    if not sniffing:
        return
    
    # Check if packet is IPv4
    if packet.haslayer(IP):
        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Get protocol
        protocol = packet[IP].proto

        # Protocol mapping for better readability
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(protocol, str(protocol))

        # Check if Raw layer exists
        if packet.haslayer(Raw):
            payload_bytes = packet[Raw].load
            payload_hex = binascii.hexlify(payload_bytes).decode('utf-8', 'ignore')
        else:
            payload_hex = ""  # Set payload to an empty string if not present

        # Add packet information to the GUI
        text_area.insert(tk.END, f"Source IP: {source_ip}\n")
        text_area.insert(tk.END, f"Destination IP: {destination_ip}\n")
        text_area.insert(tk.END, f"Protocol: {protocol_name}\n")
        text_area.insert(tk.END, f"Payload (Hex): {payload_hex}\n")
        text_area.insert(tk.END, "-" * 32 + "\n")

def start_sniffing():
    global sniffing
    sniffing = True
    try:
        sniff(filter="ip", prn=packet_analysis, stop_filter=lambda _: not sniffing)
    except PermissionError:
        messagebox.showerror("Permission Error", "You need to run this script with administrative privileges.")
    sniffing = False

def stop_sniffing():
    global sniffing
    sniffing = False

def start_button_clicked():
    start_button.config(state=tk.DISABLED)  # Disable start button
    stop_button.config(state=tk.NORMAL)     # Enable stop button
    threading.Thread(target=start_sniffing).start()

def stop_button_clicked():
    global sniffing
    sniffing = False
    start_button.config(state=tk.NORMAL)    # Enable start button
    stop_button.config(state=tk.DISABLED)   # Disable stop button

# GUI setup
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("800x600")
root.configure(bg='black')  # Set background color to black

# Create a scrolled text area for displaying packets
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Arial", 12), bg='black', fg='white')
text_area.pack(fill=tk.BOTH, expand=True)

# Create a start button
start_button = tk.Button(root, text="Start Sniffing", font=("Arial", 14), command=start_button_clicked)
start_button.pack(pady=10)
start_button.configure(bg='grey', fg='white')  # Set button colors

# Create a stop button
stop_button = tk.Button(root, text="Stop Sniffing", font=("Arial", 14), command=stop_button_clicked, state=tk.DISABLED)
stop_button.pack(pady=10)
stop_button.configure(bg='red', fg='white')    # Set button colors

# Start the GUI main loop
root.mainloop()