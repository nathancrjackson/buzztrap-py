#!/usr/bin/python3

from lib_printlog import plog
from lib_appconfig import AppConfig
from lib_unixsocketclient import UnixSocketClient
from lib_applifecyclemanager import AppLifecycleManager
from lib_getmac import get_mac_address

import traceback
import socket
import threading
import datetime
import json
import os

import paramiko

'''
Based on internetwache/SSH-Honeypot/honeypot.py, copyright (c) 2015 internetwache.org
Provided under the MIT License
'''

APP_NAME = 'SSH BuzzTrap'
APP_AUTHOR = 'Nathan Jackson @ DTC Group'
APP_VERSION = '251217'
APP_CONFIG = None

app_config = AppConfig(
	config_file = './data/buzztrap_ssh.ini',
	defaults = {
		'SOCKET_PATH': './data/buzztrap.sock',
		'SSH_IP': '0.0.0.0',
		'SSH_PORT': '2222',
		'SSH_KEYFILE': './data/server.key',
		'SSH_BANNER': 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.13', # Banner for SSH to Ubuntu 24.04
		'LOG_FILE': './logs/buzztrap_ssh.log',
		'LOG_FILEMODE': 'a',
		'LOG_DEBUG': 'false'
	},
	required = [],
	cast_bool = ['LOG_DEBUG'],
	cast_int = ['SSH_PORT'],
	cast_float = []
)

class SSHServerHandler(paramiko.ServerInterface):
	# Handles SSH authentication requests
	def __init__(self):
		self.event = threading.Event()
		self.conn_requests = 0
		self.auth_attempts = 0

	# Tells the user they have to use password authentication
	def get_allowed_auths(self, username):
		self.conn_requests = self.conn_requests + 1
		plog.info(f"Connection request: {username}")
		return 'password'

	# Tells the user that the attempt failed
	def check_auth_password(self, username, password):
		self.auth_attempts = self.auth_attempts + 1
		plog.info(f"Authentication attempt: {username}")
		#plog.info(f"Authentication attempt: {username}:{password}")
		return paramiko.AUTH_FAILED

class SSHHoneyPot:
	def __init__(self, listening_ip, listening_port, host_key, unixsocket_client):
		self.listening_ip = listening_ip
		self.listening_port = listening_port
		self.host_key = host_key
		self.unixsocket_client = unixsocket_client
		self.network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.network_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.network_socket.bind((listening_ip, listening_port))
		self.network_socket.listen(10)
		self.network_socket.settimeout(3)
		self.show_ready = True

		plog.info(f"Honeypot ready to listening for SSH connections on {listening_ip}:{listening_port}")
	
	def listen_for_connections(self):
		try:
			if self.show_ready:
				plog.info(f"Honeypot is listening for SSH connections")
			network_connection, source_details = self.network_socket.accept()
		except socket.timeout:
			# Socket should timeout every 3 seconds, then come into here and redo the loop
			self.show_ready = False
			return True
		except OSError:
			return False

		# Use the modern threading.Thread class
		client_thread = threading.Thread(
			target=self.handle_connection,
			args=(network_connection, source_details)
		)
		client_thread.daemon = True # Allows main thread to exit even if clients are connected
		client_thread.start()

		self.show_ready = True

		return True
		
	# Manage our individual client connections
	def handle_connection(self, client, client_addr):

		# Once we have a tug on the line
		timestamp_string = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
		source_address = client_addr[0].strip()
		source_mac = get_mac_address(ip=source_address)
		source_port = client_addr[1]
		plog.warning("Connection from: {0}:{1} [{2}]".format(source_address, source_port, source_mac))

		try:
			transport = paramiko.Transport(client)
			channel = None

			# Override the default paramiko banner with something else
			transport.local_version = APP_CONFIG['SSH_BANNER']

			transport.add_server_key(self.host_key)
			server_handler = SSHServerHandler()
			transport.start_server(server=server_handler)

			try:
				while transport.is_active():
					channel = transport.accept(2)
					if channel:
						break
			finally:
				if channel is not None:
					channel.close()
				transport.close()
		
		except Exception as e:
			plog.error(f"Exception during connection handling for {client_addr[0]}: {e}")
		finally:
			entry = {"timestamp": timestamp_string,
						"honeypot": "SSH",
						"proto": "TCP",
						"src_ip": source_address,
						"src_mac": source_mac,
						"src_port": source_port,
						"dst_ip": self.listening_ip,
						"dst_port": self.listening_port,
						"conns": server_handler.conn_requests,
						"auths": server_handler.auth_attempts
						}
			entry_string = json.dumps(entry)

			plog.debug("timestamp: {}, src_ip: {}, src_mac: {}, src_port: {}, dst_ip: {}, dst_port: {}, conns: {}, auths: {}".format(
				timestamp_string,
				source_address,
				source_mac,
				source_port,
				self.listening_ip,
				self.listening_port,
				server_handler.conn_requests,
				server_handler.auth_attempts)
			)
			self.unixsocket_client.sendall(entry_string)

			plog.info(f"Closed SSH connection from {source_address}:{source_port}")

def main():
	# Check for the host key file. If it doesn't exist, generate it automatically.
	if not os.path.exists(APP_CONFIG['SSH_KEYFILE']):
		plog.warning(f"Host key not found at '{APP_CONFIG['SSH_KEYFILE']}'. Generating a new 2048-bit RSA key...")
		try:
			# Generate a new 2048-bit RSA key
			new_key = paramiko.RSAKey.generate(2048)
		except Exception as e:
			plog.error(f"Failed to generate the host key: {e}")
			return
		try:
			# Save it to the configured path
			new_key.write_private_key_file(APP_CONFIG['SSH_KEYFILE'])
			plog.info(f"Successfully generated and saved new host key.")
		except Exception as e:
			plog.error(f"Failed to save host key: {e}")
			return

	try:
		host_key = paramiko.RSAKey(filename=APP_CONFIG['SSH_KEYFILE'])
	except Exception as e:
		plog.error(f"Failed to load host key '{APP_CONFIG['SSH_KEYFILE']}': {e}")
		return

	applifecycle_manager = AppLifecycleManager()
	applifecycle_manager.setup_signals()

	unixsocket_client = UnixSocketClient(APP_CONFIG['SOCKET_PATH'], applifecycle_manager.run_cleanup)
	if not unixsocket_client.connect():
		return

	ssh_honeypot = SSHHoneyPot(APP_CONFIG['SSH_IP'], APP_CONFIG['SSH_PORT'], host_key, unixsocket_client)

	applifecycle_manager.register_cleanup(unixsocket_client.close)
	applifecycle_manager.register_cleanup(ssh_honeypot.network_socket.close)

	applifecycle_manager.run_mainloop(ssh_honeypot, 'listen_for_connections')

	plog.info(f"{APP_NAME} has stopped listening")

if __name__ == "__main__":
	try:
		APP_CONFIG = app_config.process()
		run_main = True
	except Exception as e:
		plog.critical(e)

	try:
		if run_main:
			plog.info(f"Starting {APP_NAME} v{APP_VERSION}")

			if APP_CONFIG['LOG_DEBUG'] == True:
				plog.info(f"Written by {APP_AUTHOR}")
				plog.warning("Debug mode is ON")

			main()
	except Exception as e:
		error_message = f"An error occurred: {e}"
		error_trace = traceback.format_exc()
		plog.critical(error_message)
		plog.critical(error_trace)