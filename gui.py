# === Simple Network Sniffer GUI with GeoIP + WHOIS + Block IP + Reverse DNS (Auto) ===
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk, simpledialog
import threading
from scapy.all import sniff, IP, TCP, UDP, ARP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import geoip2.database
from ipwhois import IPWhois
import socket
import os

# === Basic Setup ===
sniffing = False
ip_logs = []
other_logs = []
stats = {"TCP": 0, "UDP": 0, "ARP": 0, "Other": 0}
filter_option = "All"

# === GeoIP Setup ===
try:
    geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
    def geo_lookup(ip):
        try:
            resp = geo_reader.city(ip)
            return f"{resp.city.name}, {resp.country.name}"
        except:
            return "Unknown"
except:
    geo_reader = None
    def geo_lookup(ip):
        return "GeoIP DB not found"

# === Reverse DNS Auto ===
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "-"

# === WHOIS (Extracted Info Only) ===
def whois_lookup():
    ip_or_domain = simpledialog.askstring("WHOIS Lookup", "Enter an IP or domain:")
    if ip_or_domain:
        try:
            if any(c.isalpha() for c in ip_or_domain):  # Domain lookup
                import whois
                w = whois.whois(ip_or_domain)
                messagebox.showinfo("WHOIS Result", str(w))
            else:  # IP lookup
                obj = IPWhois(ip_or_domain)
                result = obj.lookup_rdap()

                org = result.get("network", {}).get("name", "N/A")
                abuse_emails = set()

                objects = result.get("objects", {})
                if isinstance(objects, dict):
                    for val in objects.values():
                        contact = val.get("contact")
                        if isinstance(contact, dict):
                            email_val = contact.get("email")
                            if isinstance(email_val, dict):
                                email = email_val.get("value")
                                if email:
                                    abuse_emails.add(email)

                        remarks = val.get("remarks")
                        if isinstance(remarks, list):
                            for remark in remarks:
                                if isinstance(remark, dict):
                                    for line in remark.get("description", []):
                                        if "@" in line:
                                            abuse_emails.add(line.strip())

                msg = f"Org: {org}\n\nAbuse Emails:\n" + ("\n".join(abuse_emails) if abuse_emails else "None found")
                messagebox.showinfo("WHOIS Result", msg)

        except Exception as e:
            messagebox.showerror("Error", f"WHOIS lookup failed:\n{e}")



# === Reverse DNS Manual ===
def reverse_dns():
    ip = simpledialog.askstring("Reverse DNS", "Enter IP address:")
    if ip:
        try:
            host = socket.gethostbyaddr(ip)[0]
            messagebox.showinfo("Reverse DNS Result", f"{ip} → {host}")
        except socket.herror:
            messagebox.showinfo("Reverse DNS Result", f"{ip} has no reverse DNS entry.")
        except Exception as e:
            messagebox.showerror("Error", f"Reverse DNS lookup failed:\n{e}")

# === Block IP (Windows only) ===
def block_ip():
    ip = simpledialog.askstring("Block IP", "Enter IP address to block:")
    if ip:
        try:
            os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=out interface=any action=block remoteip={ip}")
            messagebox.showinfo("Success", f"IP {ip} blocked via firewall")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to block IP: {e}")

# === Handle Packets ===
def handle_packet(packet):
    if not sniffing:
        return
    try:
        if packet.haslayer(IP):
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
            if filter_option in ("All", proto):
                stats[proto] += 1
                src = packet[IP].src
                dst = packet[IP].dst
                src_geo = geo_lookup(src)
                dst_geo = geo_lookup(dst)
                src_host = resolve_hostname(src)
                dst_host = resolve_hostname(dst)
                log = f"[{proto}] {src} ({src_geo} | {src_host}) -> {dst} ({dst_geo} | {dst_host})\n"
                ip_logs.append(log)
                ip_output.insert(tk.END, log)
                ip_output.see(tk.END)
        elif packet.haslayer(ARP) and filter_option in ("All", "ARP"):
            stats["ARP"] += 1
            log = f"[ARP] {packet[ARP].psrc} -> {packet[ARP].pdst}\n"
            ip_logs.append(log)
            ip_output.insert(tk.END, log)
            ip_output.see(tk.END)
        elif filter_option == "All":
            stats["Other"] += 1
            log = f"[{packet.name}] {packet.summary()}\n"
            other_logs.append(log)
            other_output.insert(tk.END, log)
            other_output.see(tk.END)
        update_stats()
        update_chart()
    except:
        pass

def start_sniff():
    global sniffing
    sniffing = True
    clear_all()
    ip_output.insert(tk.END, "[+] Sniffing started...\n")
    threading.Thread(target=lambda: sniff(prn=handle_packet, store=False), daemon=True).start()

def stop_sniff():
    global sniffing
    sniffing = False
    ip_output.insert(tk.END, "[-] Sniffing stopped.\n")

def clear_all():
    ip_output.delete('1.0', tk.END)
    other_output.delete('1.0', tk.END)
    ip_logs.clear()
    other_logs.clear()
    for k in stats: stats[k] = 0
    update_stats()
    update_chart()

def save_log():
    name = filedialog.asksaveasfilename(defaultextension=".txt")
    if name:
        with open(name, "w", encoding="utf-8") as f:
            f.write("-- IP Packets --\n" + "".join(ip_logs))
            f.write("\n-- Other Packets --\n" + "".join(other_logs))
        messagebox.showinfo("Saved", "Log saved successfully!")

def update_stats():
    stat_label.config(text=f"TCP: {stats['TCP']}  UDP: {stats['UDP']}  ARP: {stats['ARP']}  Other: {stats['Other']}")

def update_chart():
    ax.clear()
    ax.bar(stats.keys(), stats.values(), color=['green','orange','blue','gray'])
    ax.set_title("Packet Types")
    chart.draw()

def change_filter(event):
    global filter_option
    filter_option = filter_box.get()
    clear_all()

# === GUI ===
app = tk.Tk()
app.title("Simple Network Sniffer")
app.geometry("1100x700")

header = tk.Label(app, text="Network Packet Sniffer", font=("Arial", 18, "bold"), bg="#222", fg="white")
header.pack(fill=tk.X)

# Frames
main = tk.Frame(app)
main.pack(fill=tk.BOTH, expand=True)

left = tk.Frame(main)
left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

right = tk.Frame(main, width=400)
right.pack(side=tk.RIGHT, fill=tk.BOTH)

# IP Log
tk.Label(left, text="IP/TCP/UDP/ARP Packets", font=("Arial", 12)).pack()
ip_output = scrolledtext.ScrolledText(left, font=("Courier", 10))
ip_output.pack(fill=tk.BOTH, expand=True)

# Other Log
tk.Label(right, text="Other Packets", font=("Arial", 12)).pack()
other_output = scrolledtext.ScrolledText(right, font=("Courier", 10), height=10)
other_output.pack(fill=tk.BOTH, expand=True)

# Stats + Chart
stat_label = tk.Label(right, text="", font=("Arial", 12), fg="blue")
stat_label.pack(pady=5)

fig, ax = plt.subplots(figsize=(4, 2))
chart = FigureCanvasTkAgg(fig, master=right)
chart.get_tk_widget().pack()

# Controls
controls = tk.Frame(app)
controls.pack(fill=tk.X, pady=10)

filter_box = ttk.Combobox(controls, values=["All", "TCP", "UDP", "ARP"], state="readonly")
filter_box.set("All")
filter_box.pack(side=tk.LEFT, padx=5)
filter_box.bind("<<ComboboxSelected>>", change_filter)

tk.Button(controls, text="▶ Start", command=start_sniff, bg="green", fg="white", width=10).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="■ Stop", command=stop_sniff, bg="red", fg="white", width=10).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="🧹 Clear", command=clear_all, width=10).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="💾 Save", command=save_log, bg="blue", fg="white", width=10).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="🌐 WHOIS", command=whois_lookup, bg="#444", fg="white", width=10).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="🔁 Reverse DNS", command=reverse_dns, bg="#555", fg="white", width=12).pack(side=tk.LEFT, padx=5)
tk.Button(controls, text="⛔ Block IP", command=block_ip, bg="black", fg="white", width=10).pack(side=tk.LEFT, padx=5)

update_stats()
update_chart()
app.mainloop()