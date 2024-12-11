import sys
import socket
import threading
import logging
import time
import tkinter as tk
from tkinter import simpledialog, scrolledtext
from chat.core.config import (
    RECONNECT_DELAY,
    MAX_RETRIES,
    CLIENT_HOST,
    TCP_PORT,
    UDP_PORT,
    BUFFER_SIZE,
    SECRET_KEY,
    IV,
)
from chat.utils.protocols import (
    encrypt_message,
    decrypt_message,
    pack_message,
    recv_message,
)

from chat.utils.loggings import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


class ChatClient:
    def __init__(self, master):
        username_arg = None
        if len(sys.argv) > 1:
            username_arg = sys.argv[1]

        if username_arg is None:
            self.username = simpledialog.askstring(
                "Username", "Enter your username:", parent=master
            )
            if not self.username:
                master.destroy()
                return
        else:
            self.username = username_arg

        self.master = master
        self.master.title("Chat Client")

        # Main layout: left_frame for online users, right_frame for chat
        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Left side (Online users)
        left_frame = tk.Frame(main_frame, width=200, bg="#f0f0f0")
        left_frame.pack(side=tk.LEFT, fill=tk.Y)
        self.online_users_label = tk.Label(
            left_frame, text="Online users: 0", bg="#f0f0f0"
        )
        self.online_users_label.pack(pady=(10, 0))
        self.online_users_list = tk.Listbox(left_frame)
        self.online_users_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Right side (Chat display and input)
        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Chat display
        self.chat_display = scrolledtext.ScrolledText(right_frame, state="disabled")
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Configure text tags for different message types
        self.chat_display.tag_config("system", foreground="green")
        self.chat_display.tag_config("left", foreground="gray")
        self.chat_display.tag_config("broadcast", foreground="red")

        # Entry and send button
        entry_frame = tk.Frame(right_frame)
        entry_frame.pack(fill=tk.X, padx=10, pady=5)

        self.entry = tk.Entry(entry_frame, font=("Arial", 12))
        self.entry.pack(side=tk.LEFT, fill=tk.X, padx=5, expand=True)
        self.entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            entry_frame, text="Send", command=self.send_message
        )
        self.send_button.pack(side=tk.RIGHT, padx=5)

        # Network variables
        self.conn = None
        self.connected = False
        self.online_users = []

        # Start UDP listener and connect to server
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # https://stackoverflow.com/questions/16217958/why-do-we-need-socketoptions-so-broadcast-to-enable-broadcast
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.udp_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )  # allow multiple clients on same machine
        self.udp_socket.bind(("", UDP_PORT))
        threading.Thread(target=self.listen_udp, daemon=True).start()
        threading.Thread(target=self.connect_to_server, daemon=True).start()

    def connect_to_server(self):
        retries = 0
        while not self.connected and retries < MAX_RETRIES:
            try:
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.conn.connect((CLIENT_HOST, TCP_PORT))
                self.send_raw_message(self.username)
                self.connected = True
                self.append_chat(f"[System] Connected as {self.username}.")
                threading.Thread(target=self.receive_messages, daemon=True).start()
                return
            except socket.error:
                retries += 1
                self.append_chat(
                    f"[System] Connection failed. Retrying: {retries}/{MAX_RETRIES}"
                )
                time.sleep(RECONNECT_DELAY)

        if not self.connected:
            self.append_chat(
                "[System] Unable to connect to the server after multiple attempts."
            )
            self.master.after(3000, self.master.destroy)
            raise ConnectionError(
                "Unable to connect to the server after multiple attempts."
            )

    def send_raw_message(self, text):
        encrypted = encrypt_message(SECRET_KEY, IV, text.encode("utf-8"))
        data = pack_message(encrypted)
        try:
            self.conn.sendall(data)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.connected = False

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg.strip():
            self.send_raw_message(msg)
            self.entry.delete(0, tk.END)

    def receive_messages(self):
        while self.connected:
            try:
                data = recv_message(self.conn)
                if data is None:
                    self.connected = False
                    self.append_chat(
                        "[System] Disconnected from server. Attempting to reconnect..."
                    )
                    self.conn.close()
                    self.conn = None
                    self.connect_to_server()
                    return
                decrypted = decrypt_message(SECRET_KEY, IV, data).decode("utf-8")

                if decrypted == "KICKED":  # Do not allow reconnection if kicked
                    self.append_chat("[System] You have been kicked out from the chat.")
                    self.connected = False
                    self.master.after(2000, self.master.destroy)
                    return

                self.append_chat(decrypted)
            except (
                Exception
            ) as e:  # FIXME: 重連機制需要調整，若這邊重連可能會有 infinite loop 的問題
                logger.error(f"Error receiving message: {e}")
                self.connected = False
                self.append_chat(
                    "[System] Error receiving message. Attempting to reconnect..."
                )
                self.connect_to_server()
                break

    def listen_udp(self):
        while True:
            data, addr = self.udp_socket.recvfrom(BUFFER_SIZE)
            msg = data.decode("utf-8")
            if msg.startswith("ONLINE_USERS:"):
                users = (
                    msg.split(":", 1)[1].split(",")
                    if len(msg.split(":", 1)) > 1 and msg.split(":", 1)[1].strip() != ""
                    else []
                )
                self.online_users = users
                self.update_online_users()

    def update_online_users(self):
        count = len(self.online_users)
        self.online_users_label.config(text=f"Online users: {count}")
        self.online_users_list.delete(0, tk.END)
        for user in self.online_users:
            self.online_users_list.insert(tk.END, user)

    def append_chat(self, text):
        self.chat_display.config(state="normal")

        if text.startswith("[System]"):
            tag = "system"
        elif "joined the chat." in text or "left the chat." in text:
            tag = "left"
        elif "[Broadcast]" in text:
            tag = "broadcast"
        else:
            tag = None

        self.chat_display.insert(tk.END, text + "\n", tag)
        self.chat_display.config(state="disabled")
        self.chat_display.yview(tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClient(root)
    root.mainloop()
