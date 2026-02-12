from lib_printlog import plog

import socket
import threading
import os

class UnixSocketServer:
	def __init__(self, socket_path, connection_handler_func, socket_server_name = "Unix Socket Server"):
		self.socket_path = socket_path
		self.connection_handler_func = connection_handler_func
		self.socket_server_name = socket_server_name
		self.unix_socket = None
		self.listener_thread = None
		self.active_clients = []
		self.show_ready = True

	def start(self):
		try:
			# Ensure the socket file doesn't exist from a previous run
			if os.path.exists(self.socket_path):
				os.remove(self.socket_path)

			# Create a Unix domain socket
			self.unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

			# Bind the socket to the file path
			self.unix_socket.bind(self.socket_path)

			# Ensure the socket can be written to
			os.chmod(self.socket_path, 0o666)

			# Listen for incoming connections
			self.unix_socket.listen(10)
			plog.info(f"Listening on Unix socket: {self.socket_path}")
		except Exception as e:
			plog.error(f"Server socket '{self.socket_path}' could not be created")
			return False

		return True		

	def accept_conns(self):
		try:
			if self.show_ready:
				plog.info(f"Accepting connections to Unix socket.")
			conn, addr = self.unix_socket.accept()
		except OSError:
			self.show_ready = False
			return False
		
		self.active_clients.append(conn)
		plog.info("Accepted connection from client.")
		
		# Create a new thread to handle this client
		# The 'target' is the function to run in the new thread
		# The 'args' is a tuple of arguments to pass to the target function
		client_thread = threading.Thread(target=self.connection_handler_func, args=(self, conn,))
		
		# Start the thread. The main loop will immediately continue
		# and wait for the next connection at unix_socket.accept()
		client_thread.start()

		self.show_ready = True
		return True

	def sendall(self, message_str: str):
		self.unix_socket.sendall(message_str.encode('utf-8'))

	def close(self):

		# Close all client connections if there are some
		if self.active_clients:
			num_conns = len(self.active_clients)
			if num_conns == 1:
				plog.info("Closing 1 active Unix socket connection")
			else:
				plog.info(f"Closing {num_conns} active Unix socket connections")

			for conn in self.active_clients:
				try:
					conn.sendall(b"shutdown")
					conn.shutdown(socket.SHUT_RDWR)
					conn.close()
					plog.debug(f"Closed active client connection")
				except Exception as e:
					plog.error(f"Error closing client: {e}")

		if self.unix_socket:
			plog.info("Closing Unix socket")
			self.unix_socket.close()
			self.unix_socket = None

		# Delete the socket file
		if os.path.exists(self.socket_path):
			os.remove(self.socket_path)