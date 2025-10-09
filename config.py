# backend/config.py
import os

# IBM Quantum token - recommended to set as env var
IBM_API_TOKEN = os.getenv("IBM_QUANTUM_TOKEN", "PASTE_YOUR_IBM_TOKEN_HERE")

# ThingSpeak channel details
THINGSPEAK_CHANNEL_ID = "3100917"
THINGSPEAK_READ_KEY   = "AT5M7WZ9WQX31AHN"
THINGSPEAK_WRITE_KEY  = "4ONVDAM8LZD1KGH0"

# Shared device/server secret
ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"

# AES configuration (must match device)
SERVER_AES_KEY_HEX = "00112233445566778899aabbccddeeff"
AES_IV_HEX         = "000102030405060708090a0b0c0d0e0f"

# ThingSpeak read count
THINGSPEAK_RESULTS = 1

# IBM runtime settings
IBM_Q_BACKEND = os.getenv("IBM_Q_BACKEND", "ibmq_qasm_simulator")
IBM_Q_SHOTS   = int(os.getenv("IBM_Q_SHOTS", "256"))
