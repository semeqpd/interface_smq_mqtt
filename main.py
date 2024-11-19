import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import paho.mqtt.publish as publish
import paho.mqtt.client as mqtt
import json
import ssl
import threading
import os

class MQTTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SEMEQ - Gateway MQTT Integration")
        self.root.configure(bg="#2E2E2E")
        
        self.label = tk.Label(root, text="SEMEQ - Gateway Commands [beta v1.0]", fg="#FFFFFF", bg="#2E2E2E")
        self.label.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(root, width=100, height=20, bg="#1E1E1E", fg="#00FF00", insertbackground="#00FF00")
        self.log_text.pack(padx=10, pady=10)

        self.frame1 = tk.Frame(root, bg="#2E2E2E")
        self.frame1.pack(pady=5)

        self.site_id_label = tk.Label(self.frame1, text="Site ID:", fg="#FFFFFF", bg="#2E2E2E")
        self.site_id_label.grid(row=0, column=0, padx=5)
        self.site_id_entry = tk.Entry(self.frame1, bg="#333333", fg="#FFFFFF")
        self.site_id_entry.grid(row=0, column=1, padx=5)

        self.gateway_id_label = tk.Label(self.frame1, text="Gateway ID:", fg="#FFFFFF", bg="#2E2E2E")
        self.gateway_id_label.grid(row=0, column=2, padx=5)
        self.gateway_id_entry = tk.Entry(self.frame1, bg="#333333", fg="#FFFFFF")
        self.gateway_id_entry.grid(row=0, column=3, padx=5)

        self.start_button = tk.Button(self.frame1, text="Start", command=self.start_listener, bg="#4CAF50", fg="#FFFFFF", width=10)
        self.start_button.grid(row=0, column=4, padx=5)

        self.stop_button = tk.Button(self.frame1, text="Stop", command=self.stop_listener, bg="#F44336", fg="#FFFFFF", width=10)
        self.stop_button.grid(row=0, column=5, padx=5)

        self.frame2 = tk.Frame(root, bg="#2E2E2E")
        self.frame2.pack(pady=5)

        self.command_label = tk.Label(self.frame2, text="Command:", fg="#FFFFFF", bg="#2E2E2E")
        self.command_label.grid(row=0, column=0, padx=5)
        self.command_entry = tk.Entry(self.frame2, bg="#333333", fg="#FFFFFF", width=70)
        self.command_entry.grid(row=0, column=1, padx=5)

        self.run_button = tk.Button(self.frame2, text="Run", command=self.publish_command, bg="#2196F3", fg="#FFFFFF", width=10)
        self.run_button.grid(row=0, column=2, padx=5)

        self.frame3 = tk.Frame(root, bg="#2E2E2E")
        self.frame3.pack(pady=5)

        self.clear_button = tk.Button(self.frame3, text="Clear", command=self.clear_log, bg="#FFC107", fg="#FFFFFF", width=10)
        self.clear_button.grid(row=0, column=0, padx=5)

        self.export_button = tk.Button(self.frame3, text="Export Log", command=self.export_log, bg="#9C27B0", fg="#FFFFFF", width=10)
        self.export_button.grid(row=0, column=1, padx=5)

        self.mqtt_host = "iot.semeq.com"
        self.mqtt_port = 8883
        self.mqtt_cafile = "root-CA.crt"
        self.mqtt_certfile = "cert.pem"
        self.mqtt_keyfile = "private_key.pem"
        self.client = None
        self.listening = False

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def clear_log(self):
        self.log_text.delete('1.0', tk.END)

    def export_log(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            log_content = self.log_text.get('1.0', tk.END)
            file_path = os.path.join(folder_selected, "mqtt_log.txt")
            with open(file_path, "w") as log_file:
                log_file.write(log_content)
            messagebox.showinfo("Export Log", f"Log exported successfully to {file_path}")

    def start_listener(self):
        site_id = self.site_id_entry.get()
        gateway_id = self.gateway_id_entry.get()

        if not site_id or not gateway_id:
            messagebox.showwarning("Input Error", "Site ID and Gateway ID must be filled.")
            return

        if not self.listening:
            self.client = mqtt.Client(protocol=mqtt.MQTTv311)
            response_topic = f"topic/planta/{site_id}/{gateway_id}"
            self.client.on_connect = lambda client, userdata, flags, rc: self.on_connect(client, userdata, flags, rc, response_topic)
            self.client.on_message = self.on_message

            ssl_context = ssl.create_default_context()
            ssl_context.load_cert_chain(certfile=self.mqtt_certfile, keyfile=self.mqtt_keyfile)
            ssl_context.load_verify_locations(cafile=self.mqtt_cafile)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED

            self.client.tls_set_context(context=ssl_context)
            self.client.connect(self.mqtt_host, self.mqtt_port, 60)

            threading.Thread(target=self.client.loop_forever).start()
            self.listening = True
            self.log(f"Started listening on {response_topic}")

    def stop_listener(self):
        if self.listening and self.client:
            self.client.disconnect()
            self.listening = False
            self.log("Stopped listening")

    def publish_command(self):
        site_id = self.site_id_entry.get()
        gateway_id = self.gateway_id_entry.get()
        command = self.command_entry.get()

        if not site_id or not gateway_id or not command:
            messagebox.showwarning("Input Error", "All fields must be filled.")
            return

        mqtt_topic = f"topic/planta/{site_id}"
        mqtt_payload = {
            "type": "remote_cmd",
            "option": "",
            "format": "json",
            "plant_id": int(site_id),
            "gw_id": int(gateway_id),
            "len": 123,
            "seq": 9,
            "data": command
        }
        mqtt_payload["len"] = len(json.dumps(mqtt_payload))
        mqtt_message = json.dumps(mqtt_payload)

        try:
            publish.single(
                mqtt_topic,
                mqtt_message,
                hostname=self.mqtt_host,
                port=self.mqtt_port,
                client_id="",
                auth=None,
                retain=True,
                qos=1,
                keepalive=60,
                tls={
                    "ca_certs": self.mqtt_cafile,
                    "certfile": self.mqtt_certfile,
                    "keyfile": self.mqtt_keyfile,
                    "tls_version": ssl.PROTOCOL_TLSv1_2  # TLS v1.2
                }
            )
            self.log(f"Command published to {mqtt_topic}: {command}")
            self.command_entry.delete(0, tk.END)  # Clear the command entry after publishing
        except Exception as e:
            self.log(f"Error publishing command: {str(e)}")

    def on_connect(self, client, userdata, flags, rc, topic):
        if rc == 0:
            self.log("Connected to AWS IoT")
            client.subscribe(topic)
            self.log(f"Subscribed to {topic}")
        else:
            self.log(f"Connection failed with code {rc}")

    def on_message(self, client, userdata, msg):
        message = msg.payload.decode("utf-8")
        self.log(f"Received message from {msg.topic}: {message}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MQTTApp(root)
    root.mainloop()
