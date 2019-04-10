import sys, os
import argparse
import logging
import configparser
import glob

from typing import List, Dict

from . import firewall_judgment, log_parser

# work-flow
# 1. suche alle IP in Logfile nach Merkmale eines Angriff
# 2. generiert UFW Befehlen aus der IPs im Schritte 1
# 3. gebe die Befehlen aus, oder sonstiges weiter Verarbeitung

# CLI options:
VERBOSITY = "verbosity"
LOG_FILES = "log_files"
LOG_PATTERN = "log_pattern"
# [judgment]
JUDGMENTS_CHAIN = "judgments_chain"
BOT_REQUEST = "bot_request"
MAX_REQUEST = "max_request"
INTERVAL_SECONDS = "interval_seconds"
DATABASE_PATH = "database_path"

# Config File
CONF_FILE = "config_file"

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
JUDGMENTS = ["path-based-judgment", "time-based-judgment"]

effective_config = {}

parser = argparse.ArgumentParser()
parser.add_argument(f"{CONF_FILE}", type=str,
                    help="Configuration file, configuration must be given by either a configuration file "+
                         f"(the positional argument {CONF_FILE}) or by CLI (optional arguments)")
parser.add_argument("-v", f"--{VERBOSITY}", default="INFO",
                    choices=LOG_LEVELS,
                    help="how much detail is printed out during processing log files")
parser.add_argument("-f", f"--{LOG_FILES}",
                    help="path to log file, which is use to judgment IP")
parser.add_argument("-p", f"--{LOG_PATTERN}",
                    help="log pattern of each line in the log file")
# [judgment]
parser.add_argument("-c", f"--{JUDGMENTS_CHAIN}", nargs="+", choices=JUDGMENTS,
                    help="chain of judgments")
parser.add_argument("-r", f"--{BOT_REQUEST}", nargs="+",
                    help="request path, which only bot request")
parser.add_argument(f"--{MAX_REQUEST}", type=int,
                    help="maximum request in a time-interval, given by '--interval_seconds'")
parser.add_argument(f"--{INTERVAL_SECONDS}", type=int,
                    help="time interval in seconds for a given maximum number of request")


def main():
    argv = sys.argv
    return do_the_job(argv[1:])


def do_the_job(argv):
    global effective_config
    logging.basicConfig(level=logging.INFO)
    ambiguous_config = f"Configuration must be given either by a configuration file [{CONF_FILE}] or by CLI option"
    if len(argv) < 1:
        parser.error(ambiguous_config)
    cli_config = parse_arg(argv)
    # Feed effective_config with cli-configurations
    effective_config = {k:v for k, v in cli_config.items() if v is not None}
    if cli_config[CONF_FILE] is not None:
        conf_file = cli_config[CONF_FILE]
        logging.info("Use additional configuration from file '%s'", conf_file)
        file_config = parse_config_file(conf_file)
        effective_config = {**file_config, **effective_config}

    # Use config
    log_level = logging.getLevelName(effective_config[VERBOSITY])
    logging.getLogger().setLevel(level=log_level)
    logging.info("Verbosity: %s %d", effective_config[VERBOSITY], log_level)
    log_files = expand_log_files(effective_config)
    logging.info(log_files)
    judgment = construct_judgment(effective_config)
    log_pattern = effective_config[LOG_PATTERN]

    for file_path in log_files:
        logging.info("Analyse file %s", file_path)
        logs = log_parser.parse_log_file(file_path, log_pattern)
        for log in logs:
            if judgment.should_deny(log):
                logging.info("Deny %s", log.ip)
    return 0


def parse_arg(argv: List[str]) -> Dict:
    args = parser.parse_args(argv)
    result = dict(vars(args))
    return result


def parse_config_file(file_path) -> Dict:
    config = configparser.ConfigParser(strict=True, interpolation=configparser.ExtendedInterpolation())
    try:
        with open(file_path) as f:
            config.read_file(f)
            d = config["DEFAULT"]
            file_config = dict(d)
            if LOG_FILES in file_config:
                file_config[LOG_FILES] = file_config[LOG_FILES].split()
            if JUDGMENTS_CHAIN in file_config:
                file_config[JUDGMENTS_CHAIN] = file_config[JUDGMENTS_CHAIN].split()
            if BOT_REQUEST in file_config:
                file_config[BOT_REQUEST] = file_config[BOT_REQUEST].split()
            if MAX_REQUEST in file_config:
                file_config[MAX_REQUEST] = int(file_config[MAX_REQUEST])
            if INTERVAL_SECONDS in file_config:
                file_config[INTERVAL_SECONDS] = int(file_config[INTERVAL_SECONDS])
            return file_config
    except IOError as ex:
        raise ParserConfigException(f"File {file_path} not exist (working dir {os.getcwd()})", ex)


class ParserConfigException(Exception):
    def __init__(self, message, errors=None):
        self.message = message
        self.errors = errors
        super(ParserConfigException, self).__init__(message)


def expand_log_files(config: Dict) -> List:
    if LOG_FILES in config:
        config_log_file = config[LOG_FILES]
        log_files = []
        for p in config_log_file:
            expand_path = glob.glob(p)
            logging.debug("expand glob '%s' to %s", p, expand_path)
            if len(expand_path) == 0:
                logging.warn("Glob path '%s' cannot be expanded to any real path", p)
            log_files = log_files + expand_path
        return log_files
    else:
        raise ParserConfigException("Log files are not configured")


def construct_judgment(config: Dict) -> firewall_judgment.AbstractIpJudgment:
    judgments_chain = config[JUDGMENTS_CHAIN] if JUDGMENTS_CHAIN in config else []
    if len(judgments_chain) < 1:
        parser.error(f"At least one of {JUDGMENTS_CHAIN} must be given")
    list_of_judgments = []
    for n in judgments_chain:
        list_of_judgments.append(judgment_by_name(n, config))
    return firewall_judgment.ChainedIpJudgment(list_of_judgments)


def judgment_by_name(name, config):
    if name == "path-based-judgment":
        bot_request_path = config[BOT_REQUEST] if BOT_REQUEST in config else []
        if len(bot_request_path) > 0:
            return firewall_judgment.PathBasedIpJudgment(bot_request_path)
        else:
            parser.error(f"At least one path in {BOT_REQUEST} must be configured if Judgment {name} is used")
    elif name == "time-based-judgment":
        if DATABASE_PATH in config:
            database_path = config[DATABASE_PATH]
            max_request = config[MAX_REQUEST] if MAX_REQUEST in config else 500
            interval = config[INTERVAL_SECONDS] if INTERVAL_SECONDS in config else 60
            return firewall_judgment.TimeBasedIpJudgment(database_path, max_request, interval)
        else:
            parser.error(f"A SQLite database ({DATABASE_PATH}) must be configured if Judgment {name} is used")
    else:
        raise ParserConfigException(f"Unknown judgment {name}")
