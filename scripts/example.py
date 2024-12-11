import subprocess
import time


def run_single_server():
    subprocess.Popen(["python", "-m", "chat.core.server"])


def run_multiple_clients(usernames):
    for name in usernames:
        subprocess.Popen(["python", "-m", "chat.core.client", name])


if __name__ == "__main__":
    run_single_server()
    time.sleep(2)  # naive wait for server to start
    user_list = ["Alice", "Bob", "Charlie"]
    run_multiple_clients(user_list)
