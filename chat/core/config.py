import os

# Network Configurations
SERVER_HOST = os.environ.get("CHAT_SERVER_HOST", "0.0.0.0")
CLIENT_HOST = os.environ.get("CHAT_CLIENT_HOST", "127.0.0.1")  # default to localhost
TCP_PORT = int(os.environ.get("CHAT_TCP_PORT", "5000"))
UDP_PORT = int(os.environ.get("CHAT_UDP_PORT", "5001"))
BUFFER_SIZE = int(
    os.environ.get("CHAT_BUFFER_SIZE", "4096")
)  # Generally 4096 or 8192 bytes is good
IDLE_TIMEOUT = int(os.environ.get("CHAT_IDLE_TIMEOUT", "60"))

# Client Configurations
RECONNECT_DELAY = 3
MAX_RETRIES = 3

# AES key and IV (Must match server and client)
SECRET_KEY = os.environ.get(
    "CHAT_SECRET_KEY", "this_is_a_32_byte_key_demo123456"
).encode("utf-8")  # 32 bytes
IV = os.environ.get("CHAT_IV", "0123456789ABCDEF").encode(
    "utf-8"
)  # Initialization Vector: 16 bytes
