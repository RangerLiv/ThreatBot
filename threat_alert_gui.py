import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext
import random
import datetime
from tkintermapview import TkinterMapView
from PIL import Image, ImageTk  
import pygame

pygame.mixer.init()


fake_alerts = [
    {"message": "Zero-day vulnerability discovered in Chrome.", "location": (37.7749, -122.4194), "severity": "High"},
    {"message": "Ransomware outbreak affecting healthcare systems in Europe.", "location": (52.5200, 13.4050), "severity": "Medium"},
    {"message": "New phishing campaign targeting financial institutions.", "location": (40.7128, -74.0060), "severity": "Low"},
    {"message": "Critical vulnerability in OpenSSL library.", "location": (51.5074, -0.1278), "severity": "High"},
    {"message": "Data breach reported by major social media platform.", "location": (34.0522, -118.2437), "severity": "Medium"},
    {"message": "Massive DDoS attack on DNS infrastructure detected.", "location": (35.6895, 139.6917), "severity": "High"},
    {"message": "🔴 0Day: Remote Code Execution in Apache HTTP Server", "location": (38.9072, -77.0369), "severity": "Critical"},
    {"message": "🟠 0Day: Kernel escalation vulnerability detected in Linux 6.1", "location": (55.7558, 37.6173), "severity": "High"},
    {"message": "🔴 0Day: Zoom zero-click exploit actively used in the wild", "location": (34.6937, 135.5023), "severity": "Critical"},
]

known_threats_info = {
    "Chrome": {"cve": "CVE-2024-12345", "tip": "Update to the latest version of Chrome."},
    "OpenSSL": {"cve": "CVE-2024-54321", "tip": "Apply the OpenSSL patch for version 3.0.2 or higher."},
    "Apache": {"cve": "CVE-2024-99999", "tip": "Disable mod_cgi and upgrade Apache immediately."},
    "Zoom": {"cve": "CVE-2024-77777", "tip": "Use Zoom version 6.2.1 or newer with zero-click protection."},
    "Linux": {"cve": "CVE-2024-88888", "tip": "Update to Linux kernel 6.1.23 or higher and restrict local access."},
}

def play_sound(path):
    pygame.mixer.music.load(path)
    pygame.mixer.music.play()

class ThreatAlertGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Threat Watch Console")
        self.root.geometry("1000x600")
        self.sound_on = True
        self.dark_mode = True
        self.severity_filter = "All"

        self.bg_color = "#1e1e1e" if self.dark_mode else "white"
        self.fg_color = "white" if self.dark_mode else "black"

        self.left_frame = tk.Frame(root, bg=self.bg_color)
        self.left_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        self.right_frame = tk.Frame(root, bg=self.bg_color)
        self.right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        self.status_label = tk.Label(self.left_frame, text="Status: Monitoring...", font=("Arial", 12), bg=self.bg_color, fg=self.fg_color)
        self.status_label.pack(pady=5)

        self.live_feed_running = True  
        self.feed_toggle_button = ctk.CTkButton(
        self.left_frame, text="Pause Feed", command=self.toggle_live_feed
)
        self.feed_toggle_button.pack(pady=5)

        self.countdown_label = ctk.CTkLabel(self.left_frame, text="Next Alert: --s", text_color="white")
        self.countdown_label.pack(pady=5)



        self.icon_state = "shield"
        self.shield_img = ctk.CTkImage(dark_image=Image.open("Assets/shield.png"), size=(40, 40))
        self.sword_img = ctk.CTkImage(dark_image=Image.open("Assets/KeyBlade.jfif"), size=(40, 40))
        self.icon_label = ctk.CTkLabel(self.left_frame, image=self.shield_img, text="", bg_color=self.bg_color)
        self.icon_label.pack(pady=5)

        self.keyblade_icon = ctk.CTkImage(dark_image=Image.open("Assets/KeyBlade.jfif"), size=(40, 40))
        self.shield_img = ctk.CTkImage(dark_image=Image.open("Assets/shield.png"), size=(40, 40))

        self.alert_area = scrolledtext.ScrolledText(self.left_frame, wrap=tk.WORD, width=60, height=20, font=("Consolas", 10), bg="black", fg="lime")
        self.alert_area.pack(pady=10)
        self.alert_area.insert(tk.END, "[System Ready] Waiting for threats...\n")
        self.alert_area.configure(state='disabled')

        self.simulate_button = tk.Button(self.left_frame, text="Simulate Threat Alert", command=self.simulate_alert, bg="red", fg="white")
        self.simulate_button.pack(pady=5)

        self.sound_toggle_button = tk.Button(self.left_frame, text="🔊 Sound: ON", command=self.toggle_sound, bg="gray", fg="white")
        self.sound_toggle_button.pack(pady=5)

        self.severity_option = tk.StringVar(value="All")
        severity_menu = tk.OptionMenu(self.left_frame, self.severity_option, "All", "Low", "Medium", "High", "Critical", command=self.set_severity_filter)
        severity_menu.config(bg="gray", fg="white")
        severity_menu.pack(pady=5)

        self.lookup_entry = tk.Entry(self.left_frame, width=30)
        self.lookup_entry.pack(pady=5)

        self.lookup_button = tk.Button(self.left_frame, text="🔍 CVE Lookup", command=self.cve_lookup, bg="gray", fg="white")
        self.lookup_button.pack(pady=5)

        self.map_widget = TkinterMapView(self.right_frame, width=400, height=400, corner_radius=10)
        self.map_widget.set_position(20.0, 0.0)
        self.map_widget.set_zoom(2)
        self.map_widget.pack(pady=10)

        self.simulate_alert()  
        self.simulated_feed_interval = self.get_random_interval()
        self.simulate_live_feed()

        self.live_feed_status = ctk.CTkLabel(self.left_frame, text="Live Feed: ON", text_color="green")
        self.live_feed_status.pack(pady=(0, 10))
       
    def set_severity_filter(self, value):
        self.severity_filter = value

    def simulate_live_feed(self):
        if self.live_feed_running:
            self.simulate_alert()
            interval = self.get_random_interval()
            self.start_countdown(interval // 1000)
            self.root.after(interval, self.simulate_live_feed)

    def toggle_sound(self):
        self.sound_on = not self.sound_on
        status = "ON" if self.sound_on else "OFF"
        self.sound_toggle_button.config(text=f"🔊 Sound: {status}")

    def simulate_alert(self, alert=None):
        if alert is None:
            severity = random.choice(["Low", "Medium", "High", "Critical"])
        alert = {
            "location": self.get_random_location(),
            "message": f"{severity} Threat Detected",
            "severity": severity
        }

    
        if self.severity_filter != "All" and alert["severity"] != self.severity_filter:
            return

    
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S]")
        self.alert_area.configure(state='normal')
        self.alert_area.insert(tk.END, f"{timestamp} ({alert['severity']}) {alert['message']}\n")
        self.alert_area.configure(state='disabled')
        self.alert_area.yview(tk.END)

    
        if self.sound_on:
            if "zero-day" in alert["message"].lower() or "0day" in alert["message"].lower():
                play_sound("MP3 Music/critical.mp3")
            else:
                play_sound("MP3 Music/priorityonemessagefromstarfleet_ep.mp3")

    
        lat, lon = alert["location"]
        self.map_widget.set_position(lat, lon)
        self.map_widget.set_zoom(5)
        self.map_widget.set_marker(lat, lon, text=alert["message"])

    
        with open("alert_log.txt", "a", encoding="utf-8") as file:
            file.write(f"{timestamp} {alert['message']}\n")
            file.write(f"Location: {lat}, {lon}\n")
            file.write(f"Severity: {alert['severity']}\n\n")

    
        self.left_frame.config(bg="red")
        self.root.after(100, lambda: self.left_frame.config(bg=self.bg_color))

    
        self.show_cve_popup(alert["message"])

    
        if alert["severity"] == "Critical":
            new_icon = self.keyblade_icon  
        else:
            new_icon = self.shield_img

            self.icon_label.configure(image=new_icon)
            self.icon_label.image = new_icon  

    
        self.root.after(10000, lambda: self.icon_label.configure(image=self.shield_img))


    def show_cve_popup(self, alert_message):
        for keyword in known_threats_info:
            if keyword.lower() in alert_message.lower():
                self.display_cve_popup(keyword)
                break

    def display_cve_popup(self, keyword):
        info = known_threats_info.get(keyword)
        if not info:
            return

        popup = tk.Toplevel(self.root)
        popup.title(f"🛡️ CVE Alert for {keyword}")
        popup.geometry("400x200")
        popup.configure(bg="black")

        msg = f"{keyword} Alert\n\nCVE: {info['cve']}\n\nTip: {info['tip']}"
        label = tk.Label(popup, text=msg, justify="left", wraplength=380, bg="black", fg="lime", font=("Consolas", 10))
        label.pack(padx=10, pady=10)

        close_btn = tk.Button(popup, text="Close", command=popup.destroy, bg="gray", fg="white")
        close_btn.pack(pady=10)

    def cve_lookup(self):
        keyword = self.lookup_entry.get().strip()
        if keyword:
            self.display_cve_popup(keyword)

    def get_random_location(self):
        return (random.uniform(-90, 90), random.uniform(-180, 180))
    
    def get_random_interval(self):
        return random.randint(180000, 1800000)  

    def pulse_icon(self):
        self.icon_size += self.pulse_direction
        if self.icon_size >= 44 or self.icon_size <= 40:
            self.pulse_direction *= -1

    
        resized = ctk.CTkImage(
        dark_image=Image.open("Assets/shield.png"),
        size=(self.icon_size, self.icon_size)
    )
        self.icon_label.configure(image=resized)
        self.icon_label.image = resized  
        self.root.after(300, self.pulse_icon)



    def load_live_feed_data(self):
        self.live_feed = [
        {
            "timestamp": "2025-04-19 12:15:00",
            "message": "Suspicious lateral movement detected on endpoint BRAVO-22",
            "severity": "High",
            "cve": "CVE-2024-21945"
        },
        {
            "timestamp": "2025-04-19 12:30:00",
            "message": "Potential zero-day exploit activity observed from IP 145.76.33.102",
            "severity": "Critical",
            "cve": "CVE-2025-00123"
        },
        {
            "timestamp": "2025-04-19 12:45:00",
            "message": "Unauthorized login attempt on secure admin console",
            "severity": "Medium",
            "cve": None
        }
    ]

    def process_next_live_alert(self):
        if hasattr(self, 'live_feed') and self.live_feed:
            next_alert = self.live_feed.pop(0)
            self.simulate_alert(alert=next_alert)
            self.root.after(10000, self.process_next_live_alert)

    def toggle_live_feed(self):
        self.live_feed_running = not self.live_feed_running

        if self.live_feed_running:
            self.feed_toggle_button.configure(text="Pause Feed")
            self.live_feed_status.configure(text="Live Feed: ON", text_color="green")
            self.simulate_live_feed()  
        else:
            self.feed_toggle_button.configure(text="Resume Feed")
            self.live_feed_status.configure(text="Live Feed: PAUSED", text_color="red")

    def start_countdown(self, seconds):
        def update():
            nonlocal seconds
            if not self.live_feed_running:
                self.countdown_label.configure(text="Next Alert: PAUSED")
                return
            if seconds <= 0:
                self.countdown_label.configure(text="Next Alert: --s")
                return
        self.countdown_label.configure(text=f"Next Alert: {seconds}s")
        seconds -= 1
        self.root.after(1000, update)

        update()


if __name__ == "__main__":
    root = ctk.CTk()
    app = ThreatAlertGUI(root)
    root.mainloop()
