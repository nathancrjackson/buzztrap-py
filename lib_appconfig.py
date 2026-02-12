from lib_printlog import plog
import configparser
import os

class AppConfig:

	def __init__(
		self,
		config_file: str,
		defaults: dict[str, str],
		required: list[str],
		cast_bool: list[str],
		cast_int: list[str],
		cast_float: list[str]
	):
		self.config_file = config_file
		self.defaults = defaults
		self.required = required
		self.cast_bool = cast_bool
		self.cast_int = cast_int
		self.cast_float = cast_float

	def process(self):
		# Prep our config
		config = {}

		# Load from ini file
		parser = configparser.ConfigParser(interpolation=None)
		if os.path.exists(self.config_file):
			parser.read(self.config_file)
			for section in parser.sections():
				for setting in parser[section]:
					config[f"{section}_{setting}".upper()] = parser[section][setting]

		# Load from environment variables over the ini
		for key, default_value in self.defaults.items():
			key = key.upper()
			config[key] = os.getenv(key) or config.get(key) or default_value

		# Start our log file
		filemode = None
		config['LOG_FILEMODE'] = config['LOG_FILEMODE'].lower()
		if config['LOG_FILEMODE'] == 'w' or config['LOG_FILEMODE'] == 'write':
			filemode = 'w'
		elif config['LOG_FILEMODE'] == 'a' or config['LOG_FILEMODE'] == 'append':
			filemode = 'a'
		else:
			plog.start_logfile(config['LOG_FILE'], self.defaults['LOG_FILEMODE'])
			raise ValueError(f"LOG_FILEMODE not \"append\" or \"write\", value is: {config['LOG_FILEMODE']}")
		plog.start_logfile(config['LOG_FILE'], filemode)

		# Check for missing values
		config_keys = config.keys()
		missing_keys = []
		for key in self.required:
			key = key.upper()
			# We need to catch the case where a required setting is handled by environmental variables
			if key not in config_keys:
				if os.getenv(key) == None:
					missing_keys.append(key)
				else:
					config[key] = os.getenv(key)
		if len(missing_keys) > 0:
			raise ValueError(f"Configuration is missing the required settings: {', '.join(missing_keys)}")

		# Run post-processing on all config values
		invalid_keys = []
		for key in config.keys():
			key = key.upper()
			# Correctly save booleans
			if key in self.cast_bool:
				if str(config[key]).lower() == 'true' or str(config[key]).lower() == 'yes':
					config[key] = True
				elif str(config[key]).lower() == 'false' or str(config[key]).lower() == 'no':
					config[key] = False
				else:
					invalid_keys.append(key)
			if key in self.cast_int:
				try:
					config[key] = int(config[key])
				except ValueError:
					invalid_keys.append(key)
			if key in self.cast_float:
				try:
					config[key] = float(config[key])
				except ValueError:
					invalid_keys.append(key)
		if len(invalid_keys) > 0:
			raise ValueError(f"Configuration setting values are invalid: {', '.join(invalid_keys)}")

		# Have to do this after config value has been cast to a boolean
		plog.set_debuglevel(config['LOG_DEBUG'])

		return config