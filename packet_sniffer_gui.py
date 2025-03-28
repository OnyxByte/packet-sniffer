import tkinter as tk
from tkinter import ttk, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from packet_sniffer_core import PacketSniffer
import threading

class PacketSnifferApp:
  def __init__(self, root):
    self.root = root
    self.root.title("Packet Sniffer")
    self.sniffer = None
    self.packet_count = 0
    self.packet_counts = []  # List to store packet counts for the graph
    self.running = False  # Flag to indicate if sniffing is active

    # GUI Setup
    self.frame = ttk.Frame(root, padding=10)
    self.frame.grid(row=0, column=0)

    ttk.Label(self.frame, text="Select Protocol:").grid(row=0, column=0, padx=5, pady=5)
    self.protocol_var = tk.StringVar(value="All")
    self.protocol_menu = ttk.Combobox(self.frame, textvariable=self.protocol_var, values=["All", "TCP", "UDP", "ICMP"], state="readonly")
    self.protocol_menu.grid(row=0, column=1, padx=5, pady=5)

    self.start_button = ttk.Button(self.frame, text="Start Sniffing", command=self.start_sniffing)
    self.start_button.grid(row=0, column=2, padx=5, pady=5)

    self.stop_button = ttk.Button(self.frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
    self.stop_button.grid(row=0, column=3, padx=5, pady=5)

    self.text_output = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD)
    self.text_output.grid(row=1, column=0, padx=10, pady=10)

    # Create a matplotlib figure for the graph
    self.fig, self.ax = plt.subplots(figsize=(5, 3))
    self.ax.set_title("Packet Count Over Time")
    self.ax.set_xlabel("Time")
    self.ax.set_ylabel("Packets Captured")
    self.graph_canvas = FigureCanvasTkAgg(self.fig, master=root)
    self.graph_canvas.get_tk_widget().grid(row=2, column=0, padx=10, pady=10)

    # Handle application close
    self.root.protocol("WM_DELETE_WINDOW", self.on_close)

  def update_gui(self, log_entry):
    # Use `after` to safely update the GUI from a background thread
    self.root.after(0, self._update_gui_safe, log_entry)

  def _update_gui_safe(self, log_entry):
    self.text_output.insert(tk.END, f"{log_entry['protocol']} Packet | {log_entry['source']} → {log_entry['destination']}\n")
    self.text_output.yview(tk.END)
    self.packet_count += 1
    self.packet_counts.append(self.packet_count)
    self.ax.clear()
    self.ax.set_title("Packet Count Over Time")
    self.ax.set_xlabel("Time")
    self.ax.set_ylabel("Packets Captured")
    self.ax.plot(self.packet_counts, marker="o", color="red")
    self.graph_canvas.draw()

  def start_sniffing(self):
    protocol = self.protocol_var.get()
    self.sniffer = PacketSniffer(protocol, self.update_gui)
    self.running = True
    threading.Thread(target=self.sniffer.start_sniffing, daemon=True).start()
    self.start_button.config(state=tk.DISABLED)
    self.stop_button.config(state=tk.NORMAL)

  def stop_sniffing(self):
    if self.sniffer:
      self.sniffer.stop_sniffing()
    self.running = False
    self.start_button.config(state=tk.NORMAL)
    self.stop_button.config(state=tk.DISABLED)

  def on_close(self):
    # Stop sniffing and close the application
    if self.running:
      self.stop_sniffing()
    self.root.destroy()

if __name__ == "__main__":
  root = tk.Tk()
  app = PacketSnifferApp(root)
  root.mainloop()
