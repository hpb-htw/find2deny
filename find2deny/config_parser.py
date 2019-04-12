import sys, os
import toml
from typing import Dict

# cli
VERBOSITY = "verbosity"
LOG_FILES = "log_files"
LOG_PATTERN = "log_pattern"
DATABASE_PATH = "database_path"

JUDGMENTS_CHAIN = "judgments_chain"
BOT_REQUEST = "bot_request"
MAX_REQUEST = "max_request"

INTERVAL_SECONDS = "interval_seconds"
UFW_PATH="ufw_cmd_script"
CONF_FILE = "config_file"

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
JUDGMENTS = ["path-based-judgment", "time-based-judgment"]


def parse_config_file(file_path:str) -> Dict:
    try:
        return toml.load(file_path)
    except IOError as ex:
        raise ParserConfigException(f"File {file_path} not exist (working dir {os.getcwd()})", ex)


class ParserConfigException(Exception):
    def __init__(self, message, errors=None):
        self.message = message
        self.errors = errors
        super(ParserConfigException, self).__init__(message)

