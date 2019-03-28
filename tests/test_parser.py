#!/usr/bin/python3


from datetime import datetime
import pprint
from .context import ip_grep


def test_parse_tomcat_log_line():
    print("start test")
    line = '127.0.0.1 134.96.214.161 - someone [27/Mar/2019:13:11:45 +0100] "GET /mathcoach/gfx/muetze.ico HTTP/1.1" 200 4286'
    pattern = '%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b'.replace('&quot;', '"').split(' ')
    entry = ip_grep.parser_tomcat_log_line(line, pattern)
    pprint.pprint(entry)
    assert entry['host'] == ip_grep.ip_to_int('127.0.0.1')
    assert entry['X-Forwarded-For'] == ip_grep.ip_to_int('134.96.214.161')
    assert entry['user'] == 'someone'
    assert entry['time'] == datetime.strptime('27/Mar/2019:13:11:45 +0100', '%d/%b/%Y:%H:%M:%S %z')
    assert entry['request'].index('GET') >=0
    assert entry['status'] == 200
    assert entry['byte'] == 4286


def test_ip_to_int():
    ip = '134.96.214.161'
    ip_int = ip_grep.ip_to_int(ip)
    print(ip_int)


def test_check_attack():
    log = {
        'host': '127.0.0.1',
        'X-Forwarded-For' : '123.206.6.9',
        'time': '27/Mar/2019:16:52:39 +0100',
        'request': 'GET /manager/html HTTP/1.1',
        'status': 401
    }
    pass
