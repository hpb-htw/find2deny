#!/usr/bin/python3

from abc import ABC, abstractmethod
import pendulum
from datetime import datetime
import ipaddress
import sqlite3
import logging

# work-flow
# 1. suche alle IP in Logfile nach Merkmale eines Angriff
# 2. generiert UFW Befehlen aus der IPs im Schritte 1
# 3. gebe die Befehlen aus, oder sonstiges weiter Verarbeitung


SQL_LITE_DATETIME_PATTERN = '%Y-%m-%d %H:%M:%S.%f%z'


def grep_tomcat_access_log(tomcat_access_path, log_pattern):
    """
    gibt eine Liste von IP in `tomcat_access_path'-Datei zurück, welche als Angriff
    eingestuft wird.

    @param tomcat_access_path: path zur Access Logfile von Tomcat, in der Regel ist die Datei ${CATALINA_BASE}/logs/localhost_access${date}.txt

    @param log_pattern: Wie in der Doku von Tomcat beschrieben (https://tomcat.apache.org/tomcat-9.0-doc/config/valve.html#Access_Logging),
    z.B:

    %h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b

    """

    log_pattern = log_pattern.replace('&quot;', '"').split(' ')
    logs = []
    num_of_line = 0
    with open(tomcat_access_path) as logfile:
        line = logfile.readline()
        num_of_line += 1
        while line:
            log_entry = parser_tomcat_log_line(line, log_pattern)
            logs.append(log_entry)
            line = logfile.readline()
    logging.debug("parsed %d lines", num_of_line)
    return logs


def parser_tomcat_log_line(log_line, pattern):
    entry = LogEntry()
    line_idx = 0
    for idx, value in enumerate(pattern):
        if value == '%h':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            logging.info("ignore pattern %s", value)
        elif value == '%{X-Forwarded-For}i':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry.ip = LogEntry.ip_to_int(entry_value)
        elif value == '%u':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry.user = entry_value
        elif value == '%t':
            (entry_value, line_idx) = _parser_sentence(log_line, line_idx, begin_quote='[', end_quote=']')
            entry.time = datetime.strptime(entry_value, '%d/%b/%Y:%H:%M:%S %z')  # TODO: parse time
        elif value == '"%r"':
            (entry_value, line_idx) = _parser_sentence(log_line, line_idx)
            entry.request = entry_value
        elif value == '%s':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry.status = int(entry_value)
        elif value == '%b':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry.byte = int(entry_value)
        else:
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            logging.info("ignore pattern %s", value)
    return entry


def _parser_word(log_line, start_idx):
    word = ''
    i = start_idx
    for i in range(start_idx, len(log_line)):
        c = log_line[i]
        if c != ' ':
            word += c
        else:
            i += 1
            break

    return (word, i)


def _parser_sentence(log_line, start_idx, begin_quote='"', end_quote='"'):
    sentence = ''
    if log_line[start_idx] != begin_quote:
        raise TypeError("Expected string")
    i = start_idx
    for i in range(start_idx + 1, len(log_line)):
        c = log_line[i]
        if c == end_quote:
            i += 2  # '"' and ' '
            break
        else:
            sentence += c
    return (sentence, i)


class LogEntry:
    """
    represents a Log Entry with following attribute:
        * 'ip': the remote IP
        * 'time': timestamp of this log entry
        * 'status': HTTP-response status of this log
        * 'request': the first line of the HTTP-request or None if not available
        * 'byte': response length in Byte
        * 'user': remote-user or None if not available
    """

    def __init__(self, ip: int = 0, time: datetime = None, status: int = 0, request: str = None, byte: int = 0,
                 user: str = None):
        self.__ip = ip
        self.__time = time
        self.__status = status
        self.__request = request
        self.__byte = byte
        self.__user = user

    @property
    def ip(self) -> int:
        """
            the IP of the log entry, represents as an interger
        :return: the ip
        """
        return self.__ip

    @ip.setter
    def ip(self, ip: str or int):
        """
            set the ip of the entry, the argument can be a string, or an integer. If the argument
            is a string, it will be converted into am integer
            # TODO: validate IP
        :param ip:
        :return:
        """
        if type(ip) == str:
            self.__ip = LogEntry.ip_to_int(ip)
        elif type(ip) == int:
            self.__ip = ip
        pass

    @property
    def time(self) -> datetime:
        """
            time of this log entry
        :return:
        """
        return self.__time

    @time.setter
    def time(self, time: str or datetime):
        """
            set time for this log entry. The argument can be a String or an instance of `datetime'
        :param time: time of this log entry
        :return:
        """
        self.__time = time

    @property
    def status(self) -> int:
        return self.__status

    @status.setter
    def status(self, status: int or str):
        self.__status = int(status)
        pass

    @property
    def request(self) -> str:
        return self.__request

    @property
    def byte(self) -> int:
        return self.__byte

    @byte.setter
    def byte(self, byte: str or int):
        self.__byte = int(byte)

    @request.setter
    def request(self, request: str):
        self.__request = request

    @property
    def user(self) -> str:
        return self.__user

    @user.setter
    def user(self, user: str):
        self.__user = user

    @property
    def iso_time(self) -> str:
        return self.__time.strftime(SQL_LITE_DATETIME_PATTERN)

    @property
    def ip_str(self):
        return LogEntry.int_to_ip(self.__ip)

    @staticmethod
    def ip_to_int(ip_str):
        """
        (2^(8*3))*a + (2^(8*2))*b + (2^8)*c + d
        :param ip_str:
        :return:
        """
        return int(ipaddress.IPv4Address(ip_str))

    @staticmethod
    def int_to_ip(ip_int):
        return str(ipaddress.IPv4Address(ip_int))

    def __getitem__(self, item):
        if item == "ip":
            return self.__ip
        elif item == "time":
            return self.__time
        elif item == "status":
            return self.__status
        elif item == "request":
            return self.__request
        elif item == "user":
            return self.__user
        elif item == "byte":
            return self.__byte
        else:
            raise KeyError("{} does not have property {}".format(self.__class__.__name__, item))

    def __setitem__(self, key, value):
        if key == "ip":
            self.ip = value
        elif key == "time":
            self.time = value
        elif key == "status":
            self.status = value
        elif key == "request":
            self.request = value
        elif key == "user":
            self.user = value
        elif key == "byte":
            self.byte = value
        else:
            raise KeyError("{} does not have property {}".format(self.__class__.__name__, key))

    def __str__(self):
        return "{} {} {} {} {} {}".format(
            LogEntry.int_to_ip(self.ip),
            self.iso_time,
            self.user,
            self.request,
            self.status,
            self.byte
        )


class AbstractIpBlocker(ABC):

    @abstractmethod
    def should_deny(self, ip):
        """
            check if the given ip should be blocked
        :param ip: in integer
        :return: True if the ip should be blocked, False if the firewall should allow ip
        """
        pass


class TimeBasedIpBlocker(AbstractIpBlocker):

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
            first_access = datetime.strptime(row['first_access'], SQL_LITE_DATETIME_PATTERN)
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
        time_iso = log_entry['time'].strftime(SQL_LITE_DATETIME_PATTERN)
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
    return pendulum.now().strftime(SQL_LITE_DATETIME_PATTERN)


def lookup_ip(ip):
    # TODO use whois service to lookup network of given ip
    return "123.456.789/24"
