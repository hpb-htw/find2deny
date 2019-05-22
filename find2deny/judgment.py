# -*- encoding:utf8 -*-

import functools
import urllib
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


def init_database(sqlite_db_path: str):
    sql_script = read_text("find2deny", "log-data.sql")
    conn = sqlite3.connect(sqlite_db_path)
    try:
        with conn:
            conn.executescript(sql_script)
    except Exception as ex:
        raise JudgmentException(f"Cannot init database in sqlite file {sqlite_db_path}")
    pass


def is_ready_blocked(log_entry: LogEntry, sqlite_db_path: str):
    @functools.lru_cache(maxsize=128)
    def __cached_query(ip: int):
        conn = sqlite3.connect(sqlite_db_path)
        try:
            with conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM block_network WHERE ip = ?", (ip,))
                row = c.fetchone()
                ip_count = row[0]
                return ip_count == 1
        except sqlite3.OperationalError as ex:
            raise JudgmentException("Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.",errors=ex)
    return __cached_query(log_entry.ip)


def update_deny(ip_network: str, log_entry: LogEntry, sqlite_db_path: str):
    # Prepare data
    # ip_network = lookup_ip(log_entry.ip)
    insert_cmd = "INSERT OR IGNORE INTO block_network (ip, ip_network, block_since) VALUES (?, ?, ?)"

    conn = sqlite3.connect(sqlite_db_path)
    # Begin Transaction
    try:
        with conn:
            conn.execute(insert_cmd, (log_entry.ip, ip_network, local_datetime()))
    except sqlite3.OperationalError as ex:
        raise JudgmentException("Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.",errors=ex)
    # finish
    logging.info("(%s) add %s to blocked network", log_entry.ip_str, ip_network)
    pass


class AbstractIpJudgment(ABC):

    @abstractmethod
    def should_deny(self, log_entry: LogEntry) -> bool:
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
        if is_ready_blocked(log_entry, self.__log_db_path):
            return True
        for judgment in self.__judgment:
            if judgment.should_deny(log_entry):
                ip_network = lookup_ip(log_entry.ip)
                update_deny(ip_network, log_entry, self.__log_db_path)
                return True
        return False


class PathBasedIpJudgment(AbstractIpJudgment):
    """

    """
    def __init__(self, bot_path: set = None):
        self._bot_path = bot_path if bot_path is not None else {}
        pass

    def should_deny(self, log_entry: LogEntry) -> bool:
        try:
            request_path = log_entry.request.split(" ")[1]
            request_resource = next( (r for r in self._bot_path if request_path.startswith(r)), None)
            blocked = request_resource is not None#any(elem.startswith(request_path) for elem in self._bot_path)
            if blocked:
                logging.info("Block %s because it tried to access %s which matches resource %s (expected as non exist)",
                             log_entry.ip_str, request_path, request_resource)
            return blocked
        except IndexError as ex:
            if log_entry.request == "-":
                return False
            else:
                logging.info("Block %s because its request >>%s<< is not conform to HTTP", log_entry.ip_str, log_entry.request)
                return True

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
            with sqlite3.connect(self._sqlite_db_path) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(sql_cmd, (log_entry.ip, log_entry.line, log_entry.log_file))
                row = c.fetchone()
                conn.commit()

                if not row or row is None:
                    return False
                else:
                    logging.debug("found %d processed ip in database log for entry %s ", row[0], log_entry)
                    ip_count = row[0]
                    return ip_count == 1
        except sqlite3.Error as ex:
            logging.warning("Cannot make connection to database file %s", self._sqlite_db_path)
            return False

    def _make_block_ip_decision(self, log_entry: LogEntry) -> bool:
        ip_int = log_entry.ip
        conn = sqlite3.connect(self._sqlite_db_path)
        conn.row_factory = sqlite3.Row
        try:
            c = conn.cursor()
            c.execute("INSERT INTO processed_log_ip (ip, line, log_file) VALUES (?, ?, ?)",
                      (log_entry.ip, log_entry.line, log_entry.log_file))
            c.execute("SELECT ip, first_access, last_access, access_count FROM log_ip WHERE ip = ?",
                      (ip_int,))
            conn.commit()
            row = c.fetchone()
            conn.close()

            if row is None:
                logging.debug("IP %s not found in log_ip", log_entry.ip_str)
                self._add_log_entry(log_entry)
                return False
            else:
                first_access = datetime.strptime(row['first_access'], DATETIME_FORMAT_PATTERN)
                delay = (log_entry.time - first_access).total_seconds()
                access_count = row['access_count'] + 1
                logging.info("%s accessed %s %s times in %d seconds", log_entry.ip_str, log_entry.request, access_count,
                             delay)
                limit_rate = self.allow_access / self.interval
                if delay > 0:
                    access_rate = access_count / delay
                    if access_rate >= limit_rate:
                        self._update_deny(log_entry, access_count)
                        logging.info(
                            "Block %s because it accessed server %d in %d secs which is too much for rate %f accesses / %f",
                            log_entry.ip_str, access_count, delay, self.allow_access, self.interval)
                        return True
                    else:
                        self._update_access(log_entry, access_count)
                        return False
                    pass
                else:
                    if access_count > self.allow_access:
                        self._update_deny(log_entry, access_count)
                        logging.info(
                            "Block %s because it accessed server %d in less than 0 secs which is too much for rate %f accesses / %f",
                            log_entry.ip_str, access_count, delay, self.allow_access, self.interval)
                        return True
                    else:
                        self._update_access(log_entry, access_count)
                        return False
        except sqlite3.OperationalError as ex:
            raise JudgmentException(
                "Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.", errors=ex)

    #TODO: Implementierung
    def _lookup_decision_cache(self, log_entry:LogEntry) -> bool:
        try:
            with sqlite3.connect(self._sqlite_db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT count(*) FROM block_network WHERE ip = ?",(log_entry.ip,))
                conn.commit()
                row = c.fetchone()
                count = row[0]
                return count == 1
        except sqlite3.OperationalError as ex:
            raise JudgmentException(
                "Access to Sqlite Db caused error; Diagnose: use `find2deny-init-db' to create a Database.", errors=ex)

    def _add_log_entry(self, log_entry: LogEntry):
        time_iso = log_entry['time'].strftime(DATETIME_FORMAT_PATTERN)
        sql_cmd = """INSERT INTO log_ip (ip, first_access, last_access, access_count) 
                                         VALUES (?, ?, ?, ?)"""
        conn = sqlite3.connect(self._sqlite_db_path)
        try:
            with conn:
                conn.execute(sql_cmd, (log_entry.ip,
                                       time_iso,
                                       time_iso,
                                       1)
                             )
        except Exception as ex:
            logging.warning("Cannot insert new log to log_ip")
        logging.info("added %s to log_ip",log_entry.ip_str)
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
        conn = sqlite3.connect(self._sqlite_db_path)
        # Begin Transaction
        try:
            with conn:
                conn.execute(update_cmd, (ip_network, log_entry.iso_time, access_count, log_entry.ip))
        except Exception as ex:
            logging.warning("Cannot update block_network")
        # finish
        pass

    def _update_access(self, log_entry: LogEntry, access_count: int):
        """

        :param log_entry:
        :param access_count:
        :return:
        """
        update_cmd = "UPDATE log_ip SET last_access = ?,  access_count = ? WHERE ip = ?"
        conn = sqlite3.connect(self._sqlite_db_path)
        try:
            with conn:
                # Begin Transaction
                conn.execute(update_cmd, (local_datetime(), access_count, log_entry.ip))
        except Exception as ex:
            print("Cannot update log_ip")
        # finish
        logging.info("update access_count of %s to %s", log_entry.ip_str, access_count)
        pass

    def __str__(self):
        return "TimeBasedIpBlocker/database:{}".format(self._sqlite_db_path)


def local_datetime() -> str:
    return pendulum.now().strftime(DATETIME_FORMAT_PATTERN)


def lookup_ip(ip: str or int) -> str:
    str_ip = ip if isinstance(ip, str) else log_parser.int_to_ip(ip)
    return __lookup_ip(str_ip)


@functools.lru_cache(maxsize=1024)
def __lookup_ip(normed_ip: str) -> str:
    try:
        who = IPWhois(normed_ip).lookup_rdap()
        return who["network"]["cidr"]
    except (urllib.error.HTTPError, exceptions.HTTPLookupError) as ex:
        logging.warn("IP Lookup for %s fail", normed_ip)
        logging.warn("return ip instead of network")
        logging.debug(ex)
        return normed_ip


class JudgmentException(Exception):
    def __init__(self, message, errors=None):
        self.message = message
        self.errors = errors
        super(JudgmentException, self).__init__(message)

