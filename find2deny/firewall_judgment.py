#!/usr/bin/python3

from abc import ABC, abstractmethod
import pendulum
from datetime import datetime
import sqlite3
import logging

from .log_parser import LogEntry, DATETIME_FORMAT_PATTERN


class AbstractIpJudgment(ABC):

    @abstractmethod
    def should_deny(self, ip):
        """
            check if the given ip should be blocked
        :param ip: in integer
        :return: True if the ip should be blocked, False if the firewall should allow ip
        """
        pass


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
        if not self._check_precondition(log_entry):
            return False
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
            self.add_log_entry(log_entry)
            return False
        else:
            first_access = datetime.strptime(row['first_access'], DATETIME_FORMAT_PATTERN)
            delay = (log_entry.time - first_access).total_seconds()
            access_count = row['access_count'] + 1
            logging.info("%s accessed %s times in %d seconds", log_entry.ip_str, access_count, delay)
            access_rate = access_count / delay
            if access_rate > (self.allow_access / self.interval):
                self.update_deny(log_entry, access_count)
                return True
            else:
                self.update_access(log_entry, access_count)
                return False
            pass
        pass

    def add_log_entry(self, log_entry: LogEntry):
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
            print("Cannot insert new log to log_ip")
        logging.info("added %s to log_ip",log_entry.ip_str)
        pass

    def update_deny(self, log_entry: LogEntry, access_count: int):
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
            print("Cannot update block_network")
        # finish
        logging.info("(%s) add %s to blocked network", log_entry.ip_str, ip_network)
        pass

    def update_access(self, log_entry: LogEntry, access_count: int):
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

    def _check_precondition(self, log_entry: LogEntry):
        return log_entry.status == 401 or log_entry.request.split(" ")[1].startswith("/manager/")

    def __str__(self):
        return "TimeBasedIpBlocker/database:{}".format(self._sqlite_db_path)


def local_datetime():
    return pendulum.now().strftime(DATETIME_FORMAT_PATTERN)


def lookup_ip(ip):
    # TODO use whois service to lookup network of given ip
    return "123.456.789/24"
