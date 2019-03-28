#!/usr/bin/python3

from datetime import datetime
import ipaddress

# work-flow
# 1. suche alle IP in Logfile nach Merkmale eines Angriff
# 2. generiert UFW Befehlen aus der IPs im Schritte 1
# 3. gebe die Befehlen aus, oder sonstiges weiter Verarbeitung


def main():
    logs = grep_tomcat_access_log('./test-data/access-log.txt', '%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b')
    print(logs)


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
    with open(tomcat_access_path) as logfile:
        line = logfile.readline()
        while line:
            log_entry = parser_tomcat_log_line(line, log_pattern)
            logs.append(log_entry)
            line = logfile.readline()

    return logs


def parser_tomcat_log_line(log_line, pattern):
    entry = {}
    line_idx = 0
    for idx, value in enumerate(pattern):
        if value == '%h':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry['host'] = ip_to_int( entry_value )
        elif value == '%{X-Forwarded-For}i':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry['X-Forwarded-For'] = ip_to_int( entry_value )
        elif value == '%u':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry['user'] = entry_value
        elif value == '%t':
            (entry_value, line_idx) = _parser_sentence(log_line, line_idx, begin_quote='[', end_quote=']')
            entry['time'] = datetime.strptime(entry_value, '%d/%b/%Y:%H:%M:%S %z') #TODO: parse time
        elif value == '"%r"':
            (entry_value, line_idx) = _parser_sentence(log_line, line_idx)
            entry['request'] = entry_value
        elif value == '%s':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry['status'] = int(entry_value)
        elif value == '%b':
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            entry['byte'] = int(entry_value)
        else:
            (entry_value, line_idx) = _parser_word(log_line, line_idx)
            # print("ignore pattern {}".format(value))
            # Nothing to do more, just skip to next word
    return entry


def _parser_word(log_line, start_idx):
    word = ''
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

    for i in range(start_idx + 1, len(log_line)):
        c = log_line[i]
        if c == end_quote:
            i += 2 # '"' and ' '
            break
        else:
            sentence += c
    return (sentence, i)


def ip_to_int(ip_str):
    """
    (2^(8*3))*a + (2^(8*2))*b + (2^8)*c + d
    :param ip_str:
    :return:
    """
    return int(ipaddress.IPv4Address(ip_str))


def int_to_ip(ip_int):
    return str(ipaddress.IPv4Address(ip_int))


if __name__ == '__main__':
    main()
