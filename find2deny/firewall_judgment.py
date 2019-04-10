#!/usr/bin/python3

from abc import ABC, abstractmethod
from typing import List
import pendulum
from datetime import datetime
import sqlite3
import logging

from ipwhois import IPWhois

from .log_parser import LogEntry, DATETIME_FORMAT_PATTERN


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

    def __init__(self, chains: List[AbstractIpJudgment]):
        self.__judgment = chains

    def should_deny(self, log_entry: LogEntry) -> bool:
        for judgment in self.__judgment:
            if judgment.should_deny(log_entry):
                return True
        return False


class PathBasedIpJudgment(AbstractIpJudgment):
    """

    """
    def __init__(self, bot_path: set = None):
        self._bot_path = bot_path if bot_path is not None else {}
        pass

    def should_deny(self, log_entry: LogEntry) -> bool:
        request_path = log_entry.request.split(" ")[1]
        return any(elem.startswith(request_path) for elem in self._bot_path)

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
        self.__init_db()

    def should_deny(self, log_entry: LogEntry) -> bool:
        """

        :param log_entry:
        :return:
        """
        conn = sqlite3.connect(self._sqlite_db_path)
        conn.row_factory = sqlite3.Row
        ip_int = log_entry.ip
        sql_cmd = "SELECT ip, first_access, last_access, access_count FROM log_ip WHERE ip = ?"
        c = conn.cursor()
        c.execute(sql_cmd, (ip_int,))
        row = c.fetchone()
        conn.commit()
        conn.close()

        if row is None:
            logging.debug("IP %s not found in database", log_entry.ip_str)
            self._add_log_entry(log_entry)
            return False
        else:
            first_access = datetime.strptime(row['first_access'], DATETIME_FORMAT_PATTERN)
            delay = (log_entry.time - first_access).total_seconds()
            access_count = row['access_count'] + 1
            logging.info("%s accessed %s times in %d seconds", log_entry.ip_str, access_count, delay)
            access_rate = access_count / delay
            if access_rate > (self.allow_access / self.interval):
                self._update_deny(log_entry, access_count)
                return True
            else:
                self._update_access(log_entry, access_count)
                return False
            pass
        pass

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
        insert_cmd = """INSERT OR IGNORE INTO block_network (ip_network, block_since) VALUES (?, ?)"""
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
                conn.execute(insert_cmd, (ip_network, local_datetime()))
                conn.execute(update_cmd, (ip_network, log_entry.iso_time, access_count, log_entry.ip))
        except Exception as ex:
            logging.warnign("Cannot update block_network")
        # finish
        logging.info("(%s) add %s to blocked network", log_entry.ip_str, ip_network)
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

    def __init_db(self):
        pass

def local_datetime() -> str:
    return pendulum.now().strftime(DATETIME_FORMAT_PATTERN)


# Global!
ip_network_cache = {}


def memoize(f):
    global ip_network_cache

    def helper(x):
        if x not in ip_network_cache:
            logging.info("Lookup %s", x)
            ip_network_cache[x] = f(x)
        return ip_network_cache[x]
    return helper


def lookup_ip(ip: str or int) -> str:
    # TODO use whois service to lookup network of given ip
    str_ip = ip if isinstance(ip, str) else LogEntry.int_to_ip(ip)

    @memoize
    def __lookup_ip(normed_ip: str) -> str:
        who = IPWhois(normed_ip).lookup_rdap()
        return who["network"]["cidr"]
    return __lookup_ip(str_ip)


