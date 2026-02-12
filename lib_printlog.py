import logging

class PrintLog:
	def __init__(self):
		self.printdebug = False

	def start_logfile(self, filename: str, filemode: str):
		logging.basicConfig(
			filename=filename,
			filemode=filemode,
			level=logging.INFO,
			format='%(asctime)s - %(levelname)s - %(message)s',
			encoding='utf-8'
		)

	def set_debuglevel(self, printdebug: bool):
		self.printdebug = printdebug
		if self.printdebug:
			logging.getLogger().setLevel(logging.DEBUG)
		else:
			logging.getLogger().setLevel(logging.INFO)

	def debug(self, message: str):
		if self.printdebug:
			print(message)
			logging.debug(message)

	def info(self, message: str):
		print(message)
		logging.info(message)

	def warning(self, message: str):
		print(message)
		logging.warning(message)

	def error(self, message: str):
		print(message)
		logging.error(message)

	def critical(self, message: str):
		print(message)
		logging.critical(message)

plog = PrintLog()