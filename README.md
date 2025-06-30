🛡️ Python Network Packet Sniffer GUI
A real-time packet sniffer built with Python, Scapy, and Tkinter — designed for learning, analysis, and detection of suspicious network activity.
Easy to use, visually interactive, and packed with essential cybersecurity features.

🚀 Features
📡 Live packet sniffing (TCP, UDP, ARP, Other)
🌐 GeoIP lookup (City & Country)
🔁 Reverse DNS auto-resolution
🌍 WHOIS lookup (IP/domain info)
📊 Live traffic chart with protocol stats
⛔ Block IPs with one click (Windows firewall)
💾 Save logs for later analysis
🧼 Clear logs with a single button
🖥️ Beginner-friendly dashboard GUI

🧠 How It Works
The tool uses:
scapy to sniff network packets
geoip2 for location lookup
socket for reverse DNS
tkinter for GUI
matplotlib for chart display
os.system to block IPs via firewall (Windows)

🛠️ Installation
git clone https://github.com/yourusername/packet-sniffer
cd packet-sniffer
pip install -r requirements.txt
python gui.py

✅ Requirements
Python 3.7+
Windows OS (for firewall block feature)
Admin/root access (to capture packets)
