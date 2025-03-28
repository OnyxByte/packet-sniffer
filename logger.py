import json
import csv
import os

LOG_JSON = "sniffer_log.json"
LOG_CSV = "sniffer_log.csv"

def save_to_json(log_entry):
  """Append a log entry to a JSON file."""
  with open(LOG_JSON, "a") as log_file:
    json.dump(log_entry, log_file)
    log_file.write("\n")

def save_to_csv(log_entry):
  """Append a log entry to a CSV file, ensuring headers are written once."""
  file_exists = os.path.exists(LOG_CSV)
  with open(LOG_CSV, "a", newline="") as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=["protocol", "source", "destination"])
    if not file_exists:
      writer.writeheader()  # Write headers only if the file is new
    writer.writerow(log_entry)
