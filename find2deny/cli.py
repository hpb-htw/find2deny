import sys, os
import argparse
import logging
import configparser
import glob

from typing import List, Dict
from pprint import pprint, pformat

from . config_parser import ParserConfigException, \
    VERBOSITY, LOG_LEVELS, CONF_FILE, \
    LOG_FILES, LOG_PATTERN, DATABASE_PATH, \
    JUDGMENT, RULES, \
    BOT_REQUEST, MAX_REQUEST, INTERVAL_SECONDS, \
    EXECUTION, SCRIPT, \
    parse_config_file

from . import log_parser
from . import judgment
from . import execution

# work-flow
# 1. suche alle IP in Logfile nach Merkmale eines Angriff
# 2. generiert UFW Befehlen aus der IPs im Schritte 1
# 3. gebe die Befehlen aus, oder sonstiges weiter Verarbeitung

# CLI options:

# [judgment]

# []

_parser = None


def main():
    global _parser
    argv = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument(f"{CONF_FILE}", type=str, nargs="?",
                        help="Configuration file, configuration must be given by a configuration file "
                        f"(the positional argument {CONF_FILE}). The Debug level can be changed by "
                        f"optional argument --{VERBOSITY}.")

    parser.add_argument("-v", f"--{VERBOSITY}", default="INFO",
                        choices=LOG_LEVELS,
                        help="how much information is printed out during processing log files")
    _parser = parser
    cli_arg = vars( parser.parse_args(argv[1:]) )
    verbosity = cli_arg[VERBOSITY]
    apply_log_config(verbosity)
    file_based_config = parse_config_file(cli_arg[CONF_FILE])
    if VERBOSITY in cli_arg: file_based_config[VERBOSITY] = verbosity
    if logging.getLogger("root").isEnabledFor(logging.DEBUG): logging.debug(pformat(file_based_config))
    validate_config(file_based_config)
    try:
        analyse_log_files(file_based_config)
    except judgment.JudgmentException as ex:
        print(ex, file=sys.stderr)


def apply_log_config(verbosity: str):
    log_level = logging.getLevelName(verbosity)
    logging.getLogger().setLevel(level=log_level)
    logging.info("Verbosity: %s %d", verbosity, log_level)


def validate_config(config: Dict):
    if LOG_FILES not in config:
        raise ParserConfigException("Log files are not configured")


#TODO: test this method
def analyse_log_files(config: Dict):
    log_files = expand_log_files(config[LOG_FILES])
    judge = construct_judgment(config)
    executor = execution.FileBasedUWFBlock(config[EXECUTION][0][RULES][SCRIPT])
    executor.begin_execute()
    log_pattern = config[LOG_PATTERN]
    for file_path in log_files:
        logging.info("Analyse file %s", file_path)
        logs = log_parser.parse_log_file(file_path, log_pattern)
        for log in logs:
            logging.debug("Process `%s'", log)
            if judgment.is_ready_blocked(log, config[DATABASE_PATH]):
                logging.info("IP %s is ready blocked", log.ip_str)
            elif judge.should_deny(log):
                network = judgment.lookup_ip(log.ip_str)
                log.network = network
                executor.block(log)
    executor.end_execute()


def expand_log_files(config_log_file: List[str]) -> List:
    log_files = []
    for p in config_log_file:
        expand_path = glob.glob(p)
        logging.debug("expand glob '%s' to %s", p, expand_path)
        if len(expand_path) == 0:
            logging.warn("Glob path '%s' cannot be expanded to any real path", p)
        log_files = log_files + expand_path
    return log_files


def construct_judgment(config) -> judgment.AbstractIpJudgment:
    judgments_chain = config[JUDGMENT] if JUDGMENT in config else []
    if len(judgments_chain) < 1:
        _parser.error(f"At least one entry in {JUDGMENT} must be configured")
    list_of_judgments = []
    for judge in judgments_chain:
        list_of_judgments += [judgment_by_name(judge, config)]
    logging.info("Use %d judgments", len(list_of_judgments))
    return judgment.ChainedIpJudgment( config[DATABASE_PATH], list_of_judgments)


def judgment_by_name(judge, config):
    name = judge['name']
    rules = judge[RULES]
    if name == "path-based-judgment":
        bot_request_path = rules[BOT_REQUEST] if BOT_REQUEST in rules else []
        if len(bot_request_path) > 0:
            return judgment.PathBasedIpJudgment(bot_request_path)
        else:
            _parser.error(f"At least one path in {BOT_REQUEST} must be configured if Judgment {name} is used")
    elif name == "time-based-judgment":
        if DATABASE_PATH in config:
            database_path = config[DATABASE_PATH]
            max_request = judge[MAX_REQUEST] if MAX_REQUEST in judge else 500
            interval = judge[INTERVAL_SECONDS] if INTERVAL_SECONDS in judge else 60
            return judgment.TimeBasedIpJudgment(database_path, max_request, interval)
        else:
            _parser.error(f"A SQLite database ({DATABASE_PATH}) must be configured in global section if Judgment {name} is used")
    else:
        raise ParserConfigException(f"Unknown judgment {name}")


#############################################################################
#############################################################################
#############################################################################
def init_db():
    global _parser
    argv = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument("db_path",
                        help="Path to an Sqlite Database")
    _parser = parser
    cli = parser.parse_args(argv[1:])
    db_path = cli.db_path
    judgment.init_database(db_path)
    pass