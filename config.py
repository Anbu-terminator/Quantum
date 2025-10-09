# backend/config.py

# HMAC key used by device for HMAC-SHA256
IBM_API_TOKEN = "iFQsHF7gsW7qbJGV2tWNQmL4zW9dVjl8wkStMt6m0sS4"

# ThingSpeak settings
THINGSPEAK_CHANNEL_ID = "3100917"
THINGSPEAK_READ_KEY = "AT5M7WZ9WQX31AHN"

# AES settings (must match ESP)
SERVER_AES_KEY_HEX = "00112233445566778899aabbccddeeff"
AES_IV_HEX = "000102030405060708090a0b0c0d0e0f"

# Optional simple auth token to protect /feeds/latest (device/frontend can include this)
ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"

# How many results to request from ThingSpeak
THINGSPEAK_RESULTS = 1
