#!/usr/bin/python3
from lib_printlog import plog
from lib_appconfig import AppConfig
from lib_unixsocketserver import UnixSocketServer
from lib_applifecyclemanager import AppLifecycleManager

import traceback
import threading
import time
import json
import re

import requests

APP_NAME = 'BuzzTrap Conductor'
APP_AUTHOR = 'Nathan Jackson @ DTC Group'
APP_VERSION = '260212'
APP_CONFIG = None

app_config = AppConfig(
	config_file = './data/buzztrap_conductor.ini',
	defaults = {
		'SOCKET_PATH': './data/buzztrap.sock',
		'SECURITY_WEBHOOKURL': '',
		'SECURITY_WEBHOOKCOOLDOWN': '30',
		'SECURITY_EVENTLOG': '',
		'SECURITY_APPROVED_BLINDSPOTS': '',
		'LOG_FILE': './logs/buzztrap_conductor.log',
		'LOG_FILEMODE': 'a',
		'LOG_DEBUG': 'false'
	},
	required = ['CONDUCTOR_ID'],
	cast_bool = ['LOG_DEBUG'],
	cast_int = ['SECURITY_WEBHOOKCOOLDOWN'],
	cast_float = []
)

class HoneyPotConductor:

	def __init__(self, conductor_id, webhook_url, webhook_cooldown, eventlog_filepath, srcs_to_ignore):

		self.conductor_id = conductor_id
		self.webhook_url = webhook_url
		self.webhook_cooldown = webhook_cooldown
		self.webhook_lasttriggered = 0
		self.webhook_enabled = False
		self.eventlog_file = None
		self.ready = True

		plog.info('Conductor ID is: '+self.conductor_id)

		self.srcs_to_ignore = []
		if srcs_to_ignore != None and srcs_to_ignore != '':
			self.srcs_to_ignore = [item.strip().lower() for item in srcs_to_ignore.split(',')]

		if webhook_url.startswith("https://"):
			self.webhook_enabled = True
			plog.info('Webhook alerts are enabled')

		if eventlog_filepath != '':
			try:
				self.eventlog_file = open(eventlog_filepath, "a")
				plog.info('Security event log is enabled')
			except OSError as e:
				plog.error(f"Could not open security event log file '{eventlog_filepath}': {e}")
				self.eventlog_file = None
				self.ready = False

		if len(self.srcs_to_ignore) == 1:
			plog.info('1 blindspot has been configured!')
		elif len(self.srcs_to_ignore) > 1:
			plog.info(str(len(self.srcs_to_ignore))+' blindspots have been configured!')

		blindspot_pattern = r"^(?:ip=(?P<ip>[\d\.:a-fA-F]+)|mac=(?P<mac>[0-9A-Fa-f:-]+))$"
		blindspot_errors = [
			item for item in self.srcs_to_ignore 
			if not re.match(blindspot_pattern, item)
		]

		if len(blindspot_errors) == 1:
			plog.error('Approved blindspot value failed regex: ' + blindspot_errors[0])
			self.ready = False
		if len(blindspot_errors) > 1:
			plog.error('Approved blindspot values failed regex: ' + ', '.join(blindspot_errors))
			self.ready = False

	def handle_client(self, unixsocket_server, conn):
		"""This function runs in a separate thread for each client."""
		plog.debug(f"Handling new client connection in thread: {threading.current_thread().name}")
		try:
			while True:
				data = conn.recv(1024)
				if not data:
					# Client disconnected
					break
				message = data.decode('utf-8')
				plog.info(f"Received from a client: {message}")

				try:
					conn_details = json.loads(message)

					if isinstance(conn_details, dict):
						conn_details['origin_service'] = 'BuzzTrap'
						conn_details['origin_host'] = self.conductor_id
						conn_details['origin_error'] = ''

					else:
						conn_details = {
							'origin_service': 'BuzzTrap',
							"origin_host": self.conductor_id,
							"origin_error": "Could not convert honeypot json message to dictionary"
						}

					bypass_security = False
					bypass_match = ""

					if conn_details['src_ip'] != None and conn_details['src_ip'] != "":
						if "ip="+conn_details['src_ip'].lower() in self.srcs_to_ignore:
							bypass_security = True
							bypass_match = "ip="+conn_details['src_ip'].lower()
					if conn_details['src_mac'] != None and conn_details['src_mac'] != "":
						if "mac="+conn_details['src_mac'].lower() in self.srcs_to_ignore:
							bypass_security = True
							if bypass_match == "":
								bypass_match = "mac="+conn_details['src_mac'].lower()
							else:
								bypass_match = bypass_match+" & mac="+conn_details['src_mac'].lower()

					if bypass_security:
						plog.info("Security bypassed for "+conn_details["honeypot"]+" honeypot trigger matching: "+bypass_match)
					else:
						if self.webhook_enabled:
							self.send_webhook(conn_details)
						if self.eventlog_file != None:
							self.add_to_eventlog(conn_details)

				except json.JSONDecodeError as e:
					plog.error(f"JSON decoding failed!\nError: {e.msg}\nPosition: {e.pos}")

				except requests.exceptions.RequestException as e:
					plog.error("Error sending data:", e)

				except Exception as e:
					plog.error("An unexpected error occurred:", str(e))


		except ConnectionResetError:
			plog.info("Client connection was forcibly closed.")
		finally:

			try:
				conn.close()
				unixsocket_server.active_clients.remove(conn)
				plog.info("Client connection closed.")
			except ValueError:
				plog.debug("Connection was not in active_clients list.")

	def close(self):
		# Close our security event log file 
		if self.eventlog_file != None:
			self.eventlog_file.close()

	def sanitize(self, value):
		if isinstance(value, str):
			# Replace double quotes to maintain key="value" integrity
			# Remove newlines to prevent log forging
			return value.replace('"', "'").replace('\n', ' ').replace('\r', '')
		return value

	def add_to_eventlog(self, conn_details):
		# Create a clean dictionary where every value is sanitized
		clean = {k: self.sanitize(v) for k, v in conn_details.items()}
		
		# Use the sanitized values to build the string
		event_details = (
			f"{clean.get('timestamp', '')} "
			f"host=\"{clean.get('origin_host', '')}\" "
			f"service=\"{clean.get('origin_service', '')}\" "
			f"honeypot=\"{clean.get('honeypot', '')}\" "
			f"proto=\"{clean.get('proto', '')}\" "
			f"src_ip=\"{clean.get('src_ip', '')}\" "
			f"src_mac=\"{clean.get('src_mac', '')}\" "
			f"src_port=\"{clean.get('src_port', '')}\" "
			f"dst_ip=\"{clean.get('dst_ip', '')}\" "
			f"dst_port=\"{clean.get('dst_port', '')}\"\n"
		)

		self.eventlog_file.write(event_details)
		self.eventlog_file.flush()

	def send_webhook(self, conn_details):
		now = time.time()
		secs_since_last_update = now - self.webhook_lasttriggered
		if secs_since_last_update > self.webhook_cooldown:
			self.webhook_lasttriggered = now

			headers = {"Content-Type": "application/json"}
			response = requests.post(self.webhook_url, json=conn_details, headers=headers, timeout=10)

			if 200 <= response.status_code < 300:
				if self.webhook_cooldown > 0:
					plog.info(f"Webhook sent successfully, entering cooldown for {self.webhook_cooldown} seconds")
				else:
					plog.debug("Webhook sent successfully")
			else:
				plog.error(f"Failed to send payload to webhook with status code: {response.status_code}")
				plog.error(f"Response text:{response.text}")

		else:
			time_left_in_cooldown = round(self.webhook_cooldown - secs_since_last_update, 2)
			plog.debug(f"Webhook still in cooldown, updates will skip for another {time_left_in_cooldown} seconds")

def main():

	applifecycle_manager = AppLifecycleManager()
	applifecycle_manager.setup_signals()

	honeypot_conductor = HoneyPotConductor(APP_CONFIG['CONDUCTOR_ID'], APP_CONFIG['SECURITY_WEBHOOKURL'], APP_CONFIG['SECURITY_WEBHOOKCOOLDOWN'], APP_CONFIG['SECURITY_EVENTLOG'], APP_CONFIG['SECURITY_APPROVED_BLINDSPOTS'])

	if honeypot_conductor.ready:
		unixsocket_server = UnixSocketServer(APP_CONFIG['SOCKET_PATH'], honeypot_conductor.handle_client)
		if not unixsocket_server.start():
			return

		applifecycle_manager.register_cleanup(unixsocket_server.close)
		applifecycle_manager.register_cleanup(honeypot_conductor.close)

		applifecycle_manager.run_mainloop(unixsocket_server, 'accept_conns')

		plog.info(f"{APP_NAME} has stopped accepting connections")
	else:
		plog.info(f"Cannot start {APP_NAME} as errors are stopping it from being ready")

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