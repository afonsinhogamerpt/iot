import ssl
import paho.mqtt.client as mqtt

def on_connect(client, userdata, flags, rc):
    print(f"[MQTT] Connected with code {rc}")

client = mqtt.Client()
client.username_pw_set("ricardo", "ricardo")

# Cria o contexto SSL explicitamente, ignorando validação
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

client.tls_set_context(context)

client.on_connect = on_connect

try:
    client.connect("2.tcp.eu.ngrok.io", 18065, 60)  # seu endereço e porta do ngrok TCP
    client.loop_start()
except Exception as e:
    print(f"Connection failed: {e}")

import time
time.sleep(10)
client.loop_stop()
