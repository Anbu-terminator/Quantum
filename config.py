# backend/config.py
# Replace values as needed. Keep this file secret.

IBM_API_TOKEN = "iFQsHF7gsW7qbJGV2tWNQmL4zW9dVjl8wkStMt6m0sS4"

THINGSPEAK_CHANNEL_ID = "3100917"
THINGSPEAK_READ_KEY   = "AT5M7WZ9WQX31AHN"
THINGSPEAK_WRITE_KEY  = "4ONVDAM8LZD1KGH0"

ESP_AUTH_TOKEN = "6772698c38270a210fabf1133fc6ad00"

# Server AES key (16 bytes hex) used to re-encrypt the record before storage.
SERVER_AES_KEY_HEX = "00112233445566778899aabbccddeeff"

# Key rotation settings
KEY_ROTATE_SECONDS = 60   # rotate quantum key every 60 seconds
KEEP_KEYS = 10            # keep last 10 keys
