import ipaddress
from datetime import datetime
import logging


DATETIME_FORMAT_PATTERN = '%Y-%m-%d %H:%M:%S.%f%z'


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

    def __init__(self, ip: int = 0,
                 time: datetime = None,
                 status: int = 0,
                 request: str = None,
                 byte: int = 0,
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
        return self.__time.strftime(DATETIME_FORMAT_PATTERN)

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


def parse_log_file(log_file_path, log_pattern):
    """
    gibt eine Liste von IP in `tomcat_access_path'-Datei zurück, welche als Angriff
    eingestuft wird.

    @param log_file_path: path zur Access Logfile von Tomcat, in der Regel ist die Datei ${CATALINA_BASE}/logs/localhost_access${date}.txt

    @param log_pattern: Wie in der Doku von Tomcat beschrieben (https://tomcat.apache.org/tomcat-9.0-doc/config/valve.html#Access_Logging),
    z.B:

    %h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b

    """

    log_pattern = log_pattern.replace('&quot;', '"').split(' ')
    logs = []
    num_of_line = 0
    with open(log_file_path) as logfile:
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
    host = None
    proxy_host = None

    for idx, value in enumerate(pattern):
        if value == '%h':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            host = entry_value
            proxy_host = None
            logging.debug("Capture host %s", host)
        elif value == '%{X-Forwarded-For}i':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            proxy_host = entry_value
            logging.debug("Capture proxy_host %s", proxy_host)
            host = None
        elif value == '%u':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry.user = entry_value
        elif value == '%t':
            (entry_value, line_idx) = _parser_sentence(log_line, line_idx, begin_quote='[', end_quote=']')
            entry.time = datetime.strptime(entry_value, '%d/%b/%Y:%H:%M:%S %z')
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
            logging.debug("ignore pattern %s", value)

    # update ip at the last attribute
    logging.debug("host=%s proxy=%s", host, proxy_host)
    if proxy_host is not None:
        logging.debug("use proxy_host %s", proxy_host)
        entry.ip = LogEntry.ip_to_int(proxy_host)
    else:
        logging.debug("use host %s", host)
        entry.ip = LogEntry.ip_to_int(host)

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
