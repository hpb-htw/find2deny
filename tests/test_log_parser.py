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
    entry = log_parser.parser_tomcat_log_line(line, pattern)
    logging.debug("%s", entry)
    assert entry['ip'] == log_parser.LogEntry.ip_to_int('134.96.214.161')

    assert entry['user'] == 'someone'
    assert entry['time'] == datetime.strptime('27/Mar/2019:13:11:45 +0100', '%d/%b/%Y:%H:%M:%S %z')
    assert entry['request'].index('GET') >=0
    assert entry['status'] == 200
    assert entry['byte'] == 4286


#TODO: make test use https://hypothesis.readthedocs.io/en/latest/quickstart.html
def test_ip_to_int():
    ip = '134.96.214.161'
    ip_int = log_parser.LogEntry.ip_to_int(ip)
    print(ip_int)
    assert ip_int > 0


def test_read_gz_file():
    file_path = "test-data/apache2/access.log.2.gz"
    file_reader = log_parser.open_log_file_fn(file_path)
    #text_line = None
    with file_reader(file_path) as f:
        text_line = f.readline()
    assert isinstance(text_line, str)
    assert text_line is not None
    assert text_line.strip() == '159.224.5.133 - - [30/Mar/2019:06:45:42 +0000] "GET / HTTP/1.0" 200 1219 "-" "-"'

