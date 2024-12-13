import struct
import logging
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from chat.core.config import BUFFER_SIZE, SECRET_KEY, IV
import socket

logger = logging.getLogger(__name__)

# ==============================================================================
# ref: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# - AES-CBC + PKCS7 padding used for encryption/decryption here.
# - AES (Advanced Encryption Standard) is a block cipher standardized by NIST. AES is both fast, and cryptographically strong. It is a good default choice for encryption.
# - CBC (Cipher Block Chaining) is a mode of operation for block ciphers. It is considered cryptographically strong.
# ==============================================================================


def encrypt_message(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # padding is required for CBC mode
    padded_data = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_message(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()


def pack_message(msg_bytes: bytes) -> bytes:
    # first 4 bytes is the length of the message allowing receiver to know how much to read
    # !I is a big-endian unsigned integer (4 bytes) for network byte order
    length = len(msg_bytes)
    return struct.pack("!I", length) + msg_bytes


def send_message(conn: socket.socket, message: str):
    encrypted = encrypt_message(SECRET_KEY, IV, message.encode("utf-8"))
    msg = pack_message(encrypted)
    try:
        conn.sendall(msg)  # automatically sends in chunks if message is too large
    except Exception as e:
        logger.warning(f"Failed to send message: {e}")


# ref: https://docs.python.org/zh-tw/3.12/howto/sockets.html
def recv_message(conn: socket.socket, buffer_size: int = BUFFER_SIZE):
    """Receive message from connection. First 4 bytes is the length of the message and the rest is the message itself.

    Args:
        conn (socket): A socket connection object
        buffer_size (int): Integer specifying the maximum number of bytes to receive at once
                    (defaults to BUFFER_SIZE constant)
    Returns:
        bytes: The complete message as bytes if successfully received
        None: If the connection is closed or an error occurs
    """
    try:
        header = conn.recv(4)
        if not header:
            return None
        length = struct.unpack("!I", header)[0]
        data = b""
        while len(data) < length:
            chunk = conn.recv(buffer_size)
            logger.debug(f"Received chunk: {chunk} with length: {len(chunk)}")
            if not chunk:
                return None
            data += chunk
        return data
    except Exception as e:
        logger.warning(f"Failed to receive message: {e}")
        return None


class ChatState(Enum):
    MANUAL_KICKED = "MANUAL_KICKED"
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    SERVER_SHUTDOWN = "SERVER_SHUTDOWN"
    TIMEOUT = "TIMEOUT"
