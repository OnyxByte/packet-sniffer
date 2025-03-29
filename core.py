import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
from logger import save_to_json, save_to_csv

class PacketSniffer:
  def __init__(self, protocol, callback):
    """
    Initialize the PacketSniffer with a protocol and a callback function.
    """
    self.sniffing = False
    self.protocol = protocol
    self.callback = callback
    self.sniff_thread = None

  def packet_callback(self, packet):
    """
    Callback function to process each captured packet.
    """
    if IP in packet:
      src_ip = packet[IP].src
      dst_ip = packet[IP].dst
      protocol = "OTHER"

      if TCP in packet:
        protocol = "TCP"
      elif UDP in packet:
        protocol = "UDP"
      elif ICMP in packet:
        protocol = "ICMP"

      log_entry = {"protocol": protocol, "source": src_ip, "destination": dst_ip}

      # Save the log entry to JSON and CSV
      save_to_json(log_entry)
      save_to_csv(log_entry)

      # Call the user-provided callback with the log entry
      self.callback(log_entry)

  def start_sniffing(self):
    """
    Start the packet sniffing process in a separate thread.
    """
    if self.sniffing:
      print("Sniffing is already running.")
      return

    self.sniffing = True
    protocol_filter = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "All": "ip"}.get(self.protocol, "ip")
    self.sniff_thread = threading.Thread(target=self.run_sniffing, args=(protocol_filter,), daemon=True)
    self.sniff_thread.start()

  def run_sniffing(self, protocol_filter):
    """
    Run the sniffing process with the specified protocol filter.
    """
    try:
      sniff(filter=protocol_filter, prn=self.packet_callback, store=False, stop_filter=self.should_stop_sniffing)
    except Exception as e:
      print(f"Error during sniffing: {e}")

  def should_stop_sniffing(self, packet):
    """
    Stop filter for the sniffing process.
    """
    return not self.sniffing

  def stop_sniffing(self):
    """
    Stop the packet sniffing process.
    """
    if not self.sniffing:
      print("Sniffing is not running.")
      return

    self.sniffing = False
    if self.sniff_thread and self.sniff_thread.is_alive():
      self.sniff_thread.join()  # Wait for the thread to finish
    print("Sniffing stopped.")
