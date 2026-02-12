import signal
import threading
from lib_printlog import plog

class AppLifecycleManager:
	def __init__(self):
		self.cleanup_functions = []
		self.shutdown_event = threading.Event()

	def register_cleanup(self, func):
		self.cleanup_functions.append(func)

	def setup_signals(self):
		signal.signal(signal.SIGINT, self.handle_exit)
		signal.signal(signal.SIGTERM, self.handle_exit)

	def handle_exit(self, signum, frame):
		print("")
		plog.warning(f"Running exit function, received signal: {signum}")
		self.run_cleanup()
		self.shutdown_event.set()  # signal shutdown

	def run_cleanup(self):
		for func in self.cleanup_functions:
			func()

	def run_mainloop(self, app_obj, function_name: str):
		mainloop = getattr(app_obj, function_name)
		keep_looping = True
		while not self.shutdown_event.is_set() and keep_looping:
			try:
				keep_looping = mainloop()
			except OSError:
				break