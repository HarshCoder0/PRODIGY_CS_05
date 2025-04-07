import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP
import threading


class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("800x400")

      
        self.tree = ttk.Treeview(root, columns=("src", "dst", "proto", "length"), show="headings")
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Destination IP")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("length", text="Length")
        self.tree.pack(fill=tk.BOTH, expand=True)

      
        self.button_frame = tk.Frame(root)
        self.button_frame.pack()

        self.start_btn = tk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=5)

        self.stop_btn = tk.Button(self.button_frame, text="Stop", command=self.stop_sniffing)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.sniffing = False

    def packet_callback(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            length = len(packet)

            protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
            proto_name = protocol_map.get(proto, str(proto))

            self.tree.insert('', tk.END, values=(src, dst, proto_name, length))

    def start_sniffing(self):
        self.sniffing = True
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True
        thread.start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)

    def stop_sniffing(self):
        self.sniffing = False


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()
