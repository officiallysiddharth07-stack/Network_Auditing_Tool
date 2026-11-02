import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
from scapy.all import sniff, IP, TCP, Raw
import psutil
import socket
import time
import ctypes, sys

# ================= ADMIN CHECK =================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, '"' + __file__ + '"', None, 1)
    sys.exit()

# ================= CONFIG =================
REFRESH_INTERVAL = 8000   # ms
MAX_CONNECTIONS = 50
UPLOAD_THRESHOLD = 60000

# ================= CACHES =================
dns_cache = {}
last_bytes = {}
selected_app = None

# ---------------- PROCESS LOOKUP ----------------
def get_process(port):
    try:
        for c in psutil.net_connections():
            if c.laddr and c.laddr.port == port and c.pid:
                return psutil.Process(c.pid).name()
    except:
        pass
    return "Unknown"

# ---------------- PACKET HANDLER (Tab 1) ----------------
def handle_packet(pkt, tree):
    if IP in pkt and TCP in pkt:
        port = pkt[TCP].sport
        app = get_process(port)

        payload = ""
        if Raw in pkt:
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
            except:
                payload = str(pkt[Raw].load)

        if payload.strip():
            tree.insert("", "end", values=(
                pkt[IP].src,
                pkt[IP].dst,
                port,
                app,
                payload[:200]
            ))

# ---------------- FIREWALL BLOCK (Tab 1) ----------------
def block_app():
    global selected_app
    if not selected_app:
        return
    cmd = f'netsh advfirewall firewall add rule name="BLOCK_{selected_app}" dir=out program="%ProgramFiles%\\{selected_app}" action=block'
    subprocess.run(cmd, shell=True)
    messagebox.showinfo("Blocked", f"{selected_app} blocked")

def unblock_app():
    global selected_app
    if selected_app:
        subprocess.run(f'netsh advfirewall firewall delete rule name="BLOCK_{selected_app}"', shell=True)

# ================= DNS HELPERS (Tab 2) =================
def resolve_ip(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except:
        domain = ip
    dns_cache[ip] = domain
    return domain

def block_ip(ip):
    cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)

# ================= MAIN WINDOW =================
root = tk.Tk()
root.title("Sidd's Network Defense Tool")
root.geometry("1200x600")

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# ================= TAB 1: PACKET SNIFFER =================
sniff_frame = ttk.Frame(notebook)
notebook.add(sniff_frame, text="Packet Sniffer")

cols1 = ("SRC", "DST", "PORT", "APP", "PAYLOAD")
tree1 = ttk.Treeview(sniff_frame, columns=cols1, show="headings")

for c in cols1:
    tree1.heading(c, text=c)
    tree1.column(c, width=220)

tree1.pack(fill="both", expand=True)

def on_select1(event):
    global selected_app
    item = tree1.selection()
    if item:
        selected_app = tree1.item(item)["values"][3]

tree1.bind("<<TreeviewSelect>>", on_select1)

btn_frame1 = tk.Frame(sniff_frame)
btn_frame1.pack(fill="x")

tk.Button(btn_frame1, text="BLOCK APP", command=block_app).pack(side="left", padx=10)
tk.Button(btn_frame1, text="UNBLOCK APP", command=unblock_app).pack(side="left")

# Start sniffing thread for Tab 1
def start_sniff():
    sniff(prn=lambda pkt: handle_packet(pkt, tree1), store=False)

threading.Thread(target=start_sniff, daemon=True).start()

# ================= TAB 2: CONNECTION MONITOR =================
monitor_frame = ttk.Frame(notebook)
notebook.add(monitor_frame, text="Connection Monitor")

cols2 = ("Process", "Remote IP", "Domain", "Port", "Upload Δ", "Status")
tree2 = ttk.Treeview(monitor_frame, columns=cols2, show="headings")

for col in cols2:
    tree2.heading(col, text=col)
    tree2.column(col, width=170)

tree2.pack(fill=tk.BOTH, expand=True)

def update_table():
    tree2.delete(*tree2.get_children())

    count = 0
    for c in psutil.net_connections(kind="inet"):
        if count >= MAX_CONNECTIONS:
            break
        if not c.raddr or not c.pid:
            continue

        try:
            proc = psutil.Process(c.pid)
            pname = proc.name()
            sent = proc.io_counters().write_bytes
        except:
            continue

        key = (pname, c.raddr.ip)
        prev = last_bytes.get(key, sent)
        delta = sent - prev
        last_bytes[key] = sent

        ip = c.raddr.ip
        domain = resolve_ip(ip)
        port = c.raddr.port

        status = "Normal"
        if delta > UPLOAD_THRESHOLD:
            status = "High upload activity"

        tree2.insert("", tk.END, values=(
            pname, ip, domain, port, delta, status
        ))

        count += 1

    root.after(REFRESH_INTERVAL, update_table)

def block_selected():
    sel = tree2.selection()
    if not sel:
        messagebox.showwarning("Warning", "Select a row first")
        return
    ip = tree2.item(sel[0])["values"][1]
    block_ip(ip)
    messagebox.showinfo("Blocked", f"Blocked IP: {ip}")

btn_frame2 = tk.Frame(monitor_frame)
btn_frame2.pack(pady=5)

tk.Button(btn_frame2, text="Block Selected IP", command=block_selected).pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame2, text="Refresh Now", command=update_table).pack(side=tk.LEFT, padx=10)

# Start connection monitor updates
root.after(1000, update_table)

# ================= RUN =================
root.mainloop()
#https://npcap.com/#download
