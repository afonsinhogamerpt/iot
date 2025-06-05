import paho.mqtt.client as paho
import ssl

def on_connect(client, userdata, flags, rc):
    print(f"Connected with result code {rc}")

def on_message(client, userdata, msg):
    print(f"Message: {msg.topic} {msg.payload.decode()}")

client = paho.Client()
client.username_pw_set("cristina", "cristina")
client.tls_set(cert_reqs=ssl.CERT_NONE)
client.tls_insecure_set(True)
client.on_connect = on_connect
client.on_message = on_message
client.connect("18.192.31.30", 15321, 60)
client.loop_forever()