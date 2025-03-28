# 📡 Packet Sniffer – Network Monitoring Tool

A **real-time network packet sniffer** with a user-friendly **GUI**, advanced **protocol filtering**, **JSON/CSV logging**, and **live traffic analysis**.

## 🚀 Features

- ✅ **GUI-based Packet Capture** – No command line required!
- ✅ **Protocol Selection** – Filter packets by `TCP`, `UDP`, `ICMP`, or all.
- ✅ **Real-Time Packet Display** – Monitor traffic dynamically in a scrolling log.
- ✅ **Live Traffic Graph** – Visualize packet flow over time.
- ✅ **Logging to JSON & CSV** – Store captured packets for later analysis.
- ✅ **Clean & Modular Code** – Separated into core logic, logging, and GUI.

---

## 📥 Installation

### 1️⃣ **Clone the repository**
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/packet-sniffer.git
cd packet-sniffer
```

### 2️⃣ **Install dependencies**
```bash
pip install -r requirements.txt
```

### 3️⃣ **Run the application**
```bash
python packet_sniffer_gui.py
```

📌 **Make sure you run as administrator/root to capture packets!**

---

## 📊 Live Traffic Graph
The tool includes a **real-time graph** that updates as packets are captured.

![Graph Preview](docs/graph_example.png)

---

## 🛠 Technologies Used

- **Python** 🐍
- **Scapy** – Packet sniffing
- **Tkinter** – GUI framework
- **Matplotlib** – Live graph visualization
- **Threading** – Asynchronous packet capture

---

## 📜 License
This project is **MIT licensed** – feel free to use and modify it.

---

🔹 **Give it a ⭐ on GitHub if you like it!**
