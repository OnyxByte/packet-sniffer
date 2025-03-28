def is_suspicious_packet(packet):
  """
  Check if a packet is suspicious based on its destination port.

  Args:
    packet (dict): A dictionary containing packet information.

  Returns:
    bool: True if the packet is suspicious, False otherwise.
  """
  suspicious_ports = {4444, 1337, 8080}

  # Ensure the packet is a dictionary and has a valid destination field
  if not isinstance(packet, dict):
    return False

  destination = packet.get("destination", "")
  if not isinstance(destination, str):
    return False

  try:
    # Extract the port number from the destination field
    destination_port = int(destination.split(":")[-1])
    return destination_port in suspicious_ports
  except ValueError:
    # Handle cases where the port is not a valid integer
    return False
