# server/config.py
# -------------------
# ⚠️ Keep this file secret – contains all API and encryption credentials.

# === IBM Quantum API (for key generation entropy source) ===
IBM_API_TOKEN = "iFQsHF7gsW7qbJGV2tWNQmL4zW9dVjl8wkStMt6m0sS4"

# === MongoDB (still used for key rotation logs or backup, but not for sensor data) ===
MONGODB_URI = "mongodb+srv://bastoffcial:aI4fEcricKXwBZ4f@speedo.swuhr8z.mongodb.net/"

# === ThingSpeak Configuration ===
THINGSPEAK_CHANNEL_ID = "3031584"
THINGSPEAK_READ_KEY   = "T9VU037H0SE1PG8U"
THINGSPEAK_WRITE_KEY  = "VGC3K4HUZBM7ABFZ"

# === ESP Authentication ===
ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"

# === Quantum Key Rotation Settings ===
KEY_ROTATE_SECONDS = 60     # Rotate every 60 seconds
KEEP_KEYS = 10              # Keep last 10 valid keys

# === AES CONFIG ===
SERVER_AES_KEY_HEX = "00112233445566778899aabbccddeeff"

# === Behavior Flags ===
DECRYPT_FROM_THINGSPEAK = True
STORE_ONLY_KEYS = True
