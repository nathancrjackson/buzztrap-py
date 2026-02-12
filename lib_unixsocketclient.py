from lib_printlog import plog

import socket
import threading

class UnixSocketClient:
    def __init__(self, socket_path, shutdown_callback, socket_server_name = "Unix Socket Server"):
        self.socket_path = socket_path
        self.shutdown_callback = shutdown_callback
        self.socket_server_name = socket_server_name
        self.unix_socket = None
        self.listener_thread = None

    def connect(self):
        try:
            self.unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.unix_socket.connect(self.socket_path)
            plog.info(f"Connected to Unix socket: {self.socket_path}")
            self.listener_thread = threading.Thread(target=self.listen_for_shutdown, daemon=True)
            self.listener_thread.start()
        except FileNotFoundError:
            plog.error(f"Server socket '{self.socket_path}' not found. Is the server running?")
            return False
        except ConnectionRefusedError:
            plog.error(f"Connection refused. Is the server running and listening?")
            return False
        return True

    def sendall(self, message_str: str):
        self.unix_socket.sendall(message_str.encode('utf-8'))

    def listen_for_shutdown(self):
        while True:
            data = self.unix_socket.recv(1024)
            if not data:
                plog.warning(f"{self.socket_server_name} closed the connection")
                break
            msg = data.decode('utf-8').strip()
            if msg.lower() == "shutdown":
                plog.warning(f"{self.socket_server_name} sent shutdown signal")
                break
        self.shutdown_callback()

    def close(self):
        if self.unix_socket:
            plog.info("Closing Unix socket")
            self.unix_socket.close()
            self.unix_socket = None