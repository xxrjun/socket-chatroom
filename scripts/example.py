import subprocess
import time
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_single_server():
    return subprocess.Popen(["python", "-m", "chat.core.server"])


def run_multiple_clients(usernames):
    client_processes = []
    for name in usernames:
        proc = subprocess.Popen(["python", "-m", "chat.core.client", name])
        client_processes.append(proc)
        time.sleep(1)
    return client_processes


def terminate_processes(processes):
    for proc in processes:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception as e:
            print(f"Error terminating process {proc.pid}: {e}")


if __name__ == "__main__":
    server_proc = run_single_server()
    time.sleep(2)
    user_list = ["Alice", "Bob", "Charlie"]
    client_procs = run_multiple_clients(user_list)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        terminate_processes([server_proc] + client_procs)
        logger.info("All processes terminated.")
        sys.exit(0)
