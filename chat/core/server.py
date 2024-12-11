import socket
import threading
import time
import logging
from chat.utils.loggings import setup_logging
import tkinter as tk
from tkinter import ttk
from chat.core.config import (
    SECRET_KEY,
    IV,
    SERVER_HOST,
    TCP_PORT,
    UDP_PORT,
    IDLE_TIMEOUT,
)
from chat.utils.protocols import (
    encrypt_message,
    decrypt_message,
    pack_message,
    recv_message,
)

setup_logging()
logger = logging.getLogger(__name__)

# Global state
clients = {}  # {username: (conn, addr, last_active, connected_time)}
clients_lock = threading.Lock()

running = True
server_sock = None  # global server socket


def send_message(conn, message):
    encrypted = encrypt_message(SECRET_KEY, IV, message.encode("utf-8"))
    msg = pack_message(encrypted)
    try:
        conn.sendall(msg)
    except Exception as e:
        logger.warning(f"Failed to send message: {e}")


def broadcast_message(message):
    encrypted = encrypt_message(SECRET_KEY, IV, message.encode("utf-8"))
    data = pack_message(encrypted)
    with clients_lock:
        for uname, (c, a, last_active, connected_time) in clients.items():
            try:
                c.sendall(data)
            except Exception as e:
                logger.warning(f"Failed to send message to {uname} at {a}: {e}")


def broadcast_presence():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while running:
        with clients_lock:
            online_users = list(clients.keys())
        message = "ONLINE_USERS:" + ",".join(online_users)
        try:
            udp_sock.sendto(message.encode("utf-8"), ("<broadcast>", UDP_PORT))
        except Exception as e:
            logger.warning(f"Failed to send UDP presence broadcast: {e}")
        time.sleep(5)
    udp_sock.close()


def disconnect_user(username, reason="timeout"):
    with clients_lock:
        if username in clients:
            conn, addr, la, ct = clients[username]
            if reason == "manual kick":
                send_message(conn, "KICKED")
            logger.info(f"Disconnecting {username}, Reason: {reason}")
            try:
                conn.close()
            except:
                pass
            del clients[username]


def shutdown_server():
    global running
    global server_sock
    running = False
    logger.info("Shutting down server...")
    if server_sock:
        server_sock.close()
    with clients_lock:
        for uname, (c, addr, la, ct) in list(clients.items()):
            try:
                c.close()
            except:
                pass
        clients.clear()
    logger.info("All clients disconnected. Server shutdown complete.")


def get_idle_users():
    now = time.time()
    with clients_lock:
        return [u for u, (c, a, la, ct) in clients.items() if now - la > IDLE_TIMEOUT]


def monitor_idle():
    while running:
        idle_users = get_idle_users()
        for u in idle_users:
            disconnect_user(u, "idle timeout")
        time.sleep(10)


def handle_client(conn, addr):
    username_data = recv_message(conn)
    if username_data is None:
        conn.close()
        return
    try:
        decrypted = decrypt_message(SECRET_KEY, IV, username_data)
        username = decrypted.decode("utf-8")
    except Exception as e:
        logger.error(f"Error decrypting username: {e}, Closing connection.")
        conn.close()
        return

    with clients_lock:
        if username in clients:
            send_message(conn, "ERROR: Username already taken.")
            conn.close()
            return
        clients[username] = (conn, addr, time.time(), time.time())

    logger.info(f"{username} connected from {addr}")
    broadcast_message(f"{username} joined the chat.")

    while True:
        msg = recv_message(conn)
        if msg is None:
            break
        # Update last_active
        with clients_lock:
            if username in clients:
                c, a, la, ct = clients[username]
                clients[username] = (c, a, time.time(), ct)

        try:
            decrypted = decrypt_message(SECRET_KEY, IV, msg)
            text = decrypted.decode("utf-8")
            broadcast_message(f"{username}: {text}")
        except:
            break

    disconnect_user(username, "client disconnected")
    broadcast_message(f"{username} left the chat.")
    logger.info(f"{username} disconnected from {addr}")


class ServerMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Server Monitor")

        # GUI Components
        frame_top = tk.Frame(self.root)
        frame_top.pack(padx=5, pady=5, fill=tk.X)

        self.broadcast_entry = tk.Entry(frame_top)
        self.broadcast_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(frame_top, text="Broadcast", command=self.do_broadcast).pack(
            side=tk.LEFT, padx=5
        )

        tk.Button(frame_top, text="Kick User", command=self.kick_user).pack(
            side=tk.LEFT, padx=5
        )
        tk.Button(frame_top, text="Disconnect All", command=self.disconnect_all).pack(
            side=tk.LEFT, padx=5
        )
        tk.Button(frame_top, text="Shutdown Server", command=self.shutdown).pack(
            side=tk.LEFT, padx=5
        )

        # Treeview to display connected clients
        self.tree = ttk.Treeview(
            self.root,
            columns=("username", "address", "status", "connected_time", "idle_time"),
            show="headings",
        )
        self.tree.heading("username", text="Username")
        self.tree.heading("address", text="Address")
        self.tree.heading("status", text="Status")
        self.tree.heading("connected_time", text="Connected Duration")
        self.tree.heading("idle_time", text="Idle Time")
        self.tree.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.update_clients()

    def update_clients(self):
        existing_users = {}
        for item in self.tree.get_children():
            vals = self.tree.item(item, "values")
            if vals:
                existing_users[vals[0]] = item

        now = time.time()
        with clients_lock:
            snapshot = list(clients.items())
        current_usernames = set(u for u, _ in snapshot)

        for username, (conn, addr, last_active, connected_time) in snapshot:
            connected_duration = now - connected_time
            idle_time = now - last_active
            vals = (
                username,
                f"{addr[0]}:{addr[1]}",
                "Connected",
                f"{connected_duration:.1f}s",
                f"{idle_time:.1f}s",
            )

            if username in existing_users:
                self.tree.item(existing_users[username], values=vals)
            else:
                self.tree.insert("", tk.END, values=vals)

        for username, item_id in existing_users.items():
            if username not in current_usernames:
                self.tree.delete(item_id)

        self.root.after(1000, self.update_clients)

    def kick_user(self):
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        vals = self.tree.item(item, "values")
        username = vals[0]
        disconnect_user(username, "manual kick")
        broadcast_message(f"{username} was kicked by the admin.")

    def do_broadcast(self):
        msg = self.broadcast_entry.get().strip()
        if msg:
            broadcast_message("[Broadcast] " + msg)
            self.broadcast_entry.delete(0, tk.END)

    def disconnect_all(self):
        with clients_lock:
            all_users = list(clients.keys())
        for uname in all_users:
            disconnect_user(uname, "admin command")

    def shutdown(self):
        shutdown_server()
        self.root.after(500, self.root.destroy)


def server_thread():
    global running, server_sock
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_HOST, TCP_PORT))
    server_sock.listen(5)
    logger.info(f"Listening on {SERVER_HOST}:{TCP_PORT}")

    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=monitor_idle, daemon=True).start()

    while running:
        try:
            server_sock.settimeout(1)
            conn, addr = server_sock.accept()
            threading.Thread(  # Handle client in separate thread
                target=handle_client, args=(conn, addr), daemon=True
            ).start()
        except socket.timeout:
            pass
        except OSError:
            break

    if running:
        shutdown_server()


if __name__ == "__main__":
    root = tk.Tk()
    gui = ServerMonitorGUI(root)
    threading.Thread(
        target=server_thread, daemon=True
    ).start()  # Background thread, set deamon=True to kill when main thread exits
    root.mainloop()
