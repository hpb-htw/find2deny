# -*- encoding:utf8 -*-

import functools
import urllib
import urllib.error
from abc import ABC, abstractmethod
from typing import List
import pendulum
from datetime import datetime
import sqlite3
import logging

from ipwhois import IPWhois, exceptions
from importlib_resources import read_text

from . log_parser import LogEntry, DATETIME_FORMAT_PATTERN
from . import log_parser
from . import db_connection


def init_database(sqlite_db_path: str):
    sql_script = read_text("find2deny", "log-data.sql")
    try:
        with db_connection.get_connection(sqlite_db_path) as conn:
            conn.executescript(sql_script)
    except sqlite3.OperationalError as ex:
        raise JudgmentException(f"Cannot init database in sqlite file {sqlite_db_path}", error=ex)
    pass


def is_ready_blocked(log_entry: LogEntry, sqlite_db_path: str) -> (bool, str):
    @functools.lru_cache(maxsize=2024)
    def __cached_query(ip: int):
        try:
            with db_connection.get_connection(sqlite_db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*), cause_of_block cause_of_block FROM block_network WHERE ip = ?", (ip,))
                row = c.fetchone()
                ip_count = row[0]
                cause = row[1]
                return (ip_count == 1), cause
        except sqlite3.OperationalError as ex:
            raise JudgmentException("Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.", errors=ex)
    return __cached_query(log_entry.ip)


def update_deny(ip_network: str, log_entry: LogEntry, judge:str, cause_of_block:str, sqlite_db_path: str):
    # Prepare data
    # ip_network = lookup_ip(log_entry.ip)
    insert_cmd = "INSERT OR IGNORE INTO block_network (ip, ip_network, block_since, judge, cause_of_block) VALUES (?, ?, ?, ?, ?)"
    try:
        with db_connection.get_connection(sqlite_db_path) as conn:
            conn.execute(insert_cmd, (log_entry.ip, ip_network, local_datetime(), judge, cause_of_block))
    except sqlite3.OperationalError as ex:
        raise JudgmentException("Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.",errors=ex)
    # finish
    logging.info("(%s) add %s to blocked network", log_entry.ip_str, ip_network)
    pass


class AbstractIpJudgment(ABC):

    @abstractmethod
    def should_deny(self, log_entry: LogEntry) -> (bool, str):
        """
            check if the given ip should be blocked
        :param log_entry: in integer
        :return: True if the ip should be blocked, False if the firewall should allow ip
        """
        pass


class ChainedIpJudgment(AbstractIpJudgment):

    def __init__(self, log_db_path: str, chains: List[AbstractIpJudgment]):
        self.__judgment = chains
        self.__log_db_path = log_db_path

    def should_deny(self, log_entry: LogEntry) -> bool:
        deny, cause = is_ready_blocked(log_entry, self.__log_db_path)
        if deny:
            return deny, cause
        for judgment in self.__judgment:
            deny, cause = judgment.should_deny(log_entry)
            if deny:
                ip_network = lookup_ip(log_entry.ip)
                update_deny(ip_network, log_entry,judgment.__class__.__name__, cause, self.__log_db_path)
                return True, cause
        return False, None


class PathBasedIpJudgment(AbstractIpJudgment):
    """

    """
    def __init__(self, bot_path: set = None):
        self._bot_path = bot_path if bot_path is not None else {}
        pass

    def should_deny(self, log_entry: LogEntry) -> (bool, str):
        try:
            request_path = log_entry.request.split(" ")[1]
            request_resource = next((r for r in self._bot_path if request_path.startswith(r)), None)
            blocked = request_resource is not None
            cause = None
            if blocked:
                cause = "{} tried to access {} which matches non-existing resource {}".format(
                         log_entry.ip_str, request_path, request_resource)
                logging.info(cause)
            return blocked, cause
        except IndexError:
            if log_entry.request == "-":
                return False, None
            else:
                cause = "{}-s  request >>{}<< is not conform to HTTP".format(
                             log_entry.ip_str, log_entry.request)
                logging.info(cause)
                return True, cause

    def __str__(self):
        return "PathBasedIpJudgment/bot_path:{}".format(self._bot_path)


class TimeBasedIpJudgment(AbstractIpJudgment):

    def __init__(self, path: str, allow_access: int = 10, interval_second: int = 10):
        """
        :param path: path to a SQLite Database file
        :param allow_access: number of access in a given time interval (next parameter)
        :param interval_second: time interval in seconds
        """
        self.allow_access = allow_access
        self.interval = interval_second
        self._sqlite_db_path = path

    def should_deny(self, log_entry: LogEntry) -> bool:
        """

        :param log_entry:
        :return:
        """
        if not self._ready_processed(log_entry):
            return self._make_block_ip_decision(log_entry)
        else:
            return self._lookup_decision_cache(log_entry)

    def _ready_processed(self, log_entry: LogEntry) -> bool:
        # TODO read table processed_log_ip to get Info about log_entry
        sql_cmd = "SELECT count(*) FROM processed_log_ip WHERE ip = ? AND line = ? AND log_file = ?"
        try:
            conn = db_connection.get_connection(self._sqlite_db_path)
            logging.info("Before %s", sql_cmd)
            with conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(sql_cmd, (log_entry.ip, log_entry.line, log_entry.log_file))
                row = c.fetchone()
                ## conn.commit() ##
            conn.close()
            logging.info("After %s", sql_cmd)
            if not row or row is None:
                return False
            else:
                logging.debug("found %d processed ip in database log for entry %s ", row[0], log_entry)
                ip_count = row[0]
                return ip_count == 1
        except sqlite3.OperationalError:
            logging.warning("Cannot make connection to database file %s", self._sqlite_db_path)
            return False

    def _make_block_ip_decision(self, log_entry: LogEntry) -> (bool, str):
        ip_int = log_entry.ip
        # row = None
        try:
            conn = db_connection.get_connection(self._sqlite_db_path)
            logging.info("Before Make decision")
            with conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("INSERT INTO processed_log_ip (ip, line, log_file) VALUES (?, ?, ?)",
                          (log_entry.ip, log_entry.line, log_entry.log_file))
                c.execute("SELECT ip, first_access, last_access, access_count FROM log_ip WHERE ip = ?",
                          (ip_int,))
                ## conn.commit() ##
                row = c.fetchone()
            conn.close()
            logging.info("After Make decision")
        except sqlite3.OperationalError as ex:
            raise JudgmentException(
                "Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.", errors=ex)

        if row is None:
            logging.debug("IP %s not found in log_ip", log_entry.ip_str)
            self._add_log_entry(log_entry)
            return False, None
        else:
            first_access = datetime.strptime(row['first_access'], DATETIME_FORMAT_PATTERN)
            logging.debug("log time: %s  first access: %s", log_entry.time, first_access)
            delay = (log_entry.time - first_access).total_seconds()
            delay = abs(delay)
            access_count = row['access_count'] + 1
            logging.debug("%s accessed %s %s times in %d seconds", log_entry.ip_str, log_entry.request, access_count,
                         delay)
            limit_rate = self.allow_access / self.interval
            if delay > 0:
                access_rate = access_count / delay
                if access_rate >= limit_rate:
                    cause = "{} accessed server {}-times in {} secs which is too much for rate {} accesses / {}".format(
                        log_entry.ip_str, access_count, delay, self.allow_access, self.interval)
                    self._update_deny(log_entry, access_count)
                    logging.info(cause)
                    return True, cause
                else:
                    self._update_access(log_entry, access_count)
                    return False, None
                pass
            else:
                if access_count > self.allow_access:
                    self._update_deny(log_entry, access_count)
                    cause ="{} accessed server {} in less than 0 secs which is too much for rate {} accesses / {}".format(
                        log_entry.ip_str, access_count, delay, self.allow_access, self.interval)
                    logging.info(cause)
                    return True, cause
                else:
                    self._update_access(log_entry, access_count)
                    return False, None

    def _lookup_decision_cache(self, log_entry:LogEntry) -> (bool, str):
        try:
            conn = db_connection.get_connection(self._sqlite_db_path)
            logging.info("Before select")
            with conn:
                c = conn.cursor()
                c.execute("SELECT count(*), cause_of_block FROM block_network WHERE ip = ?", (log_entry.ip,))
                ## conn.commit() ##
                row = c.fetchone()
            conn.close()
            logging.info("After select")
            count = row[0]
            cause = row[1] or None
            return (count == 1), cause
        except sqlite3.OperationalError as ex:
            raise JudgmentException(
                "Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.", errors=ex)

    def _add_log_entry(self, log_entry: LogEntry):
        time_iso = log_entry['time'].strftime(DATETIME_FORMAT_PATTERN)
        sql_cmd = """INSERT INTO log_ip (ip, first_access, last_access, access_count) 
                                         VALUES (?, ?, ?, ?)"""
        try:
            conn = db_connection.get_connection(self._sqlite_db_path)
            with conn:
                conn.execute(sql_cmd, (log_entry.ip,
                                       time_iso,
                                       time_iso,
                                       1)
                             )
                ## conn.commit() ##
            conn.close()
        except sqlite3.OperationalError:
            logging.warning("Cannot insert new log to log_ip")
        logging.info("added %s to log_ip", log_entry.ip_str)
        pass

    def _update_deny(self, log_entry: LogEntry, access_count: int):
        """
        :param log_entry:
        :param access_count:
        :return:
        """
        # Prepare data
        ip_network = lookup_ip(log_entry.ip)
        update_cmd = """UPDATE log_ip SET 
            ip_network = ?,
            last_access = ?,
            access_count = ?,
            status = 1
            WHERE ip = ?
        """
        # Begin Transaction
        try:
            with db_connection.get_connection(self._sqlite_db_path) as conn:
                conn.execute(update_cmd, (ip_network, log_entry.iso_time, access_count, log_entry.ip))
        except sqlite3.OperationalError:
            logging.warning("Cannot update log_ip")
        # finish
        pass

    def _update_access(self, log_entry: LogEntry, access_count: int):
        """

        :param log_entry:
        :param access_count:
        :return:
        """
        try:
            update_cmd = "UPDATE log_ip SET last_access = ?,  access_count = ? WHERE ip = ?"
            conn = db_connection.get_connection(self._sqlite_db_path)
            with conn:
                # Begin Transaction
                conn.execute(update_cmd, (local_datetime(), access_count, log_entry.ip))
                ## conn.commit() ##
                # finish
            conn.close()
            logging.debug("update access_count of %s to %s", log_entry.ip_str, access_count)
        except sqlite3.OperationalError:
            print("Cannot update log_ip")
        pass

    def __str__(self):
        return "TimeBasedIpBlocker/database:{}".format(self._sqlite_db_path)


def local_datetime() -> str:
    return pendulum.now().strftime(DATETIME_FORMAT_PATTERN)


def lookup_ip(ip: str or int) -> str:
    str_ip = ip if isinstance(ip, str) else log_parser.int_to_ip(ip)
    return __lookup_ip(str_ip)


@functools.lru_cache(maxsize=10240)
def __lookup_ip(normed_ip: str) -> str:
    try:
        who = IPWhois(normed_ip).lookup_rdap()
        return who["network"]["cidr"]
    except (urllib.error.HTTPError, exceptions.HTTPLookupError, exceptions.IPDefinedError) as ex:
        logging.warning("IP Lookup for %s fail", normed_ip)
        logging.warning("return ip instead of network")
        logging.debug(ex)
        return normed_ip


class JudgmentException(Exception):
    def __init__(self, message, errors=None):
        self.message = message
        self.errors = errors
        super(JudgmentException, self).__init__(message)
