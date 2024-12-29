import tkinter as tk
from scapy.all import sniff, TCP, IP
import threading
import time

# Global flag to control sniffing
sniffing = False

# Callback function to handle packets
def packet_callback(packet):
    if packet.haslayer(TCP):
        # Check if the packet has a TCP layer and the destination port is 12345
        if packet[TCP].dport == 12345:  # Detect packets on an unusual port (example)
            alert_message = f"Suspicious packet detected: {packet.summary()}"
            update_log_box(alert_message)

# Function to start sniffing in a background thread
def start_ids():
    global sniffing
    if sniffing:
        return  # If sniffing is already running, return early

    sniffing = True
    update_ui("IDS Started: Monitoring Network...", "IDS started... Monitoring network...")

    # Run the sniffing in a separate thread to avoid blocking the main UI thread
    threading.Thread(target=sniff_network, daemon=True).start()

# Function to perform the sniffing (run in a separate thread)
def sniff_network():
    """Function to start sniffing packets"""
    try:
        # Start sniffing packets and stop when 'sniffing' becomes False
        while sniffing:
            sniff(prn=packet_callback, store=0, count=10)  # Capture 10 packets at a time
            time.sleep(1)  # Sleep for a while to avoid constant sniffing
    except Exception as e:
        print(f"Error during sniffing: {e}")
    finally:
        stop_ids()  # Stop sniffing when finished or on error

# Function to stop the IDS (this will stop sniffing)
def stop_ids():
    global sniffing
    sniffing = False
    update_ui("IDS Stopped: Monitoring stopped.", "IDS stopped.")

# Function to update the log box with messages
def update_log_box(message):
    """Function to update the log box with new log messages"""
    log_box.insert(tk.END, message + '\n')
    log_box.yview(tk.END)  # Scroll to the bottom of the log box

# Function to update the UI (called via window.after to ensure it's thread-safe)
def update_ui(label_text, log_message):
    window.after(0, lambda: label.config(text=label_text))  # Update the status label in the main thread
    window.after(0, lambda: update_log_box(log_message))  # Update the log box in the main thread

# Fake Test Case Function to simulate a suspicious packet
def inject_fake_test_case():
    fake_packet = IP(src="192.168.1.100", dst="192.168.1.101") / TCP(sport=12345, dport=12345) / "Fake test data"
    packet_callback(fake_packet)  # Simulate the packet callback

# Set up the Tkinter window
window = tk.Tk()
window.title("Intrusion Detection System")
window.geometry("600x400")

# Create a label to show the status of IDS
label = tk.Label(window, text="Welcome to the IDS System", font=("Arial", 16))
label.pack(pady=20)

# Create a Text widget to show logs and alerts
log_box = tk.Text(window, width=80, height=10)
log_box.pack(pady=10)

# Create a Start button to begin packet sniffing
start_button = tk.Button(window, text="Start IDS", command=start_ids, font=("Arial", 14))
start_button.pack(side=tk.LEFT, padx=10)

# Create an Inject Fake Test Case button
fake_test_button = tk.Button(window, text="Inject Fake Test Case", command=inject_fake_test_case, font=("Arial", 14))
fake_test_button.pack(side=tk.LEFT, padx=10)

# Disable the start button if sniffing is running
start_button.config(state=tk.NORMAL)

# Start the Tkinter event loop
window.mainloop()
