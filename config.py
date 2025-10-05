# server/config.py
# -------------------
# ⚠️ Keep this file secret – contains all API and encryption credentials.

IBM_API_TOKEN = "iFQsHF7gsW7qbJGV2tWNQmL4zW9dVjl8wkStMt6m0sS4"
MONGODB_URI = "mongodb+srv://bastoffcial:aI4fEcricKXwBZ4f@speedo.swuhr8z.mongodb.net/"

THINGSPEAK_CHANNEL_ID = "3031584"
THINGSPEAK_READ_KEY   = "T9VU037H0SE1PG8U"
THINGSPEAK_WRITE_KEY  = "VGC3K4HUZBM7ABFZ"

ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"

KEY_ROTATE_SECONDS = 60
KEEP_KEYS = 10

SERVER_AES_KEY_HEX = "00112233445566778899aabbccddeeff"

DECRYPT_FROM_THINGSPEAK = True
STORE_ONLY_KEYS = True
