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


'''
Based on CommunityHoneyNetwork/rdphoney/rdp_honeyscript.py, work of Alexander Merck & Jesse Bowling
Provided under the Creative Commons CC0 1.0 Universal License
'''

APP_NAME = 'RDP BuzzTrap'
APP_AUTHOR = 'Nathan Jackson @ DTC Group'
APP_VERSION = '251217'
APP_CONFIG = None

app_config = AppConfig(
	config_file = './data/buzztrap_rdp.ini',
	defaults = {
		'SOCKET_PATH': './data/buzztrap.sock',
		'RDP_IP': '0.0.0.0',
		'RDP_PORT': '3389',
		'LOG_FILE': './logs/buzztrap_rdp.log',
		'LOG_FILEMODE': 'a',
		'LOG_DEBUG': 'false'
	},
	required = [],
	cast_bool = ['LOG_DEBUG'],
	cast_int = ['RDP_PORT'],
	cast_float = []
)

class RDPHoneyPot:
	def __init__(self, listening_ip, listening_port, unixsocket_client):
		self.listening_ip = listening_ip
		self.listening_port = listening_port
		self.unixsocket_client = unixsocket_client
		self.network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.network_socket.bind((listening_ip, listening_port))
		self.network_socket.listen(10)
		self.network_socket.settimeout(3)
		self.show_ready = True

		plog.info(f"Honeypot ready to listening for RDP connections on {listening_ip}:{listening_port}")
	
	def listen_for_connections(self):
		try:
			if self.show_ready:
				plog.info(f"Honeypot is listening for RDP connections")
			network_connection, source_details = self.network_socket.accept()
		except socket.timeout:
			# Socket should timeout every 3 seconds, then come into here and redo the loop
			self.show_ready = False
			return True
		except OSError:
			return False

		# Threading logic: Pass the connection to a handler and immediately return to listening
		client_thread = threading.Thread(
			target=self.handle_connection,
			args=(network_connection, source_details)
		)
		client_thread.daemon = True 
		client_thread.start()

		self.show_ready = True
		return True

	def handle_connection(self, network_connection, source_details):
		try:
			# Once we have a tug on the line
			timestamp_string = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			source_address = source_details[0].strip()
			source_mac = get_mac_address(ip=source_address)
			source_port = source_details[1]
			plog.warning("Connection from: {0}:{1} [{2}]".format(source_address, source_port, source_mac))

			# Receive a max of 4K data that we're going to do nothing with
			# We wrap this in a try block in case the attacker disconnects immediately
			try:
				network_connection.recv(4096)
			except OSError:
				pass

			entry = {"timestamp": timestamp_string,
						"honeypot": "RDP",
						"proto": "TCP",
						"src_ip": source_address,
						"src_mac": source_mac,
						"src_port": source_port,
						"dst_ip": self.listening_ip,
						"dst_port": self.listening_port
						}
			entry_string = json.dumps(entry)

			plog.info("timestamp: {}, src_ip: {}, src_mac: {}, src_port: {}, dst_ip: {}, dst_port: {}".format(
				timestamp_string,
				source_address,
				source_mac,
				source_port,
				self.listening_ip,
				self.listening_port)
			)
			self.unixsocket_client.sendall(entry_string)

			# Tell the client connecting that we had a negotiation error
			network_connection.send(b"0x00000004 RDP_NEG_FAILURE")
			
		except Exception as e:
			plog.error(f"Error handling RDP connection from {source_details[0]}: {e}")
		finally:
			# Ensure socket is always closed
			try:
				network_connection.shutdown(socket.SHUT_RDWR)
			except OSError:
				pass # Socket might already be closed
			network_connection.close()
			plog.info(f"Closed RDP connection from {source_details[0]}")

def main():

	applifecycle_manager = AppLifecycleManager()
	applifecycle_manager.setup_signals()

	unixsocket_client = UnixSocketClient(APP_CONFIG['SOCKET_PATH'], applifecycle_manager.run_cleanup)
	if not unixsocket_client.connect():
		return

	rdp_honeypot = RDPHoneyPot(APP_CONFIG['RDP_IP'], APP_CONFIG['RDP_PORT'], unixsocket_client)

	applifecycle_manager.register_cleanup(unixsocket_client.close)
	applifecycle_manager.register_cleanup(rdp_honeypot.network_socket.close)

	applifecycle_manager.run_mainloop(rdp_honeypot, 'listen_for_connections')

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