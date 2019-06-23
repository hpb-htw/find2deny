#!/usr/bin/python3


from datetime import datetime
import pytest
import logging
import pprint

from find2deny import log_parser


@pytest.fixture
def prepare_test_data(caplog):
    caplog.set_level(logging.INFO)
    logging.basicConfig(level=logging.INFO)
    logging.debug("prepare_test done")


def test_parse_tomcat_log_line():
    line = '127.0.0.1 134.96.214.161 - someone [27/Mar/2019:13:11:45 +0100] "GET /mathcoach/gfx/muetze.ico HTTP/1.1" 200 4286'
    pattern = '%h %{X-Forwarded-For}i %l %u %t &quot;%r&quot; %s %b'.replace('&quot;', '"').split(' ')
    entry = log_parser.parser_tomcat_log_line("no-name.log", 1024, line, pattern)
    logging.debug("%s", entry)
    assert entry['ip'] == log_parser.ip_to_int('134.96.214.161')

    assert entry['user'] == 'someone'
    assert entry['time'] == datetime.strptime('27/Mar/2019:13:11:45 +0100', '%d/%b/%Y:%H:%M:%S %z')
    assert entry['request'].index('GET') >=0
    assert entry['status'] == 200
    assert entry['byte'] == 4286


def test_parse_tomcat_log_line_with_user_agent():
    line = '93.242.172.189 - - [01/Apr/2019:07:11:42 +0000] "POST /mathcoach/ui/j_security_check HTTP/1.1" 200 738 "http://local.host/path/to/resource.html" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36"'
    pattern = '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'.split(' ')
    entry = log_parser.parser_tomcat_log_line("no-name.log", 1024, line, pattern)
    logging.debug("%s", entry)
    assert entry['ip'] == log_parser.ip_to_int('93.242.172.189')

    assert entry['user'] == '-'
    assert entry['time'] == datetime.strptime('01/Apr/2019:07:11:42 +0000', '%d/%b/%Y:%H:%M:%S %z')
    assert entry['request'].index('POST') >=0
    assert entry['status'] == 200
    assert entry['byte'] == 0 # Cannot parse '%O'
    assert entry['user_agent'] == 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86 Safari/537.36'


def test_parse_tomcat_log_line_with_user_agent_2():
    line = r'1.2.3.4 "554fcae493e564ee0dc75bdf2ebf94caads|a:3:{s:2:\"id\";s:3:\"\'/*\";s:3:\"num\";s:141:\"*/ union select 1,0x272F2A,3,4,5,6,7,8,0x7b247b24524345275d3b6469652f2a2a2f286d6435284449524543544f52595f534550415241544f5229293b2f2f7d7d,0--\";s:4:\"name\";s:3:\"ads\";}554fcae493e564ee0dc75bdf2ebf94ca"'
    print(line)
    pattern = '%h "%{Referer}i"'.split(' ')
    entry = log_parser.parser_tomcat_log_line("no-name.log", 1024, line, pattern)
    print(entry)



#TODO: make test use https://hypothesis.readthedocs.io/en/latest/quickstart.html
def test_ip_to_int():
    ip = '134.96.214.161'
    ip_int = log_parser.ip_to_int(ip)
    print(ip_int)
    assert ip_int > 0


def test_read_gz_file():
    file_path = "test-data/apache2-markov/access.log.2.gz"
    file_reader = log_parser.open_log_file_fn(file_path)
    #text_line = None
    with file_reader(file_path) as f:
        text_line = f.readline()
    assert isinstance(text_line, str)
    assert text_line is not None
    assert text_line.strip() == '159.224.5.133 - - [30/Mar/2019:06:45:42 +0000] "GET / HTTP/1.0" 200 1219 "-" "-"'


def test_ignore_bad_source_ip():
    line = 'ec2-13-233-107-164.ap-south-1.compute.amazonaws.com - - [15/May/2019:22:27:08 +0000] "GET /manager/html HTTP/1.1" 403 8036 "-" "Python-urllib/2.7"'
    pattern = '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'.split(' ')
    try:
        log_parser.parser_tomcat_log_line("no-name.log", 1024, line, pattern)
        assert False
    except log_parser.CannotParseLogIpException as ex:
        assert True