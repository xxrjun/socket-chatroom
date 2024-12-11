import struct
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from chat.core.config import BUFFER_SIZE

logger = logging.getLogger(__name__)

# AES-CBC + PKCS7 padding used for encryption/decryption here.
# more: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/


def encrypt_message(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()  # padding is required for CBC mode
    padded_data = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_message(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()


def pack_message(msg_bytes):
    # first 4 bytes is the length of the message allowing receiver to know how much to read
    # !I is a big-endian unsigned integer (4 bytes) for network byte order
    length = len(msg_bytes)
    return struct.pack("!I", length) + msg_bytes


# ref: https://docs.python.org/zh-tw/3.12/howto/sockets.html
def recv_message(conn, buffer_size=BUFFER_SIZE):
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
    except:
        return None
