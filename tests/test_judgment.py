#!/usr/bin/python3


from datetime import datetime
import time
import pytest
import logging


from find2deny import log_parser
from find2deny import judgment
import sqlite3


test_db_path = './test-data/ipdb.sqlite'
ip_data = [
    (log_parser.ip_to_int('1.2.3.4'), '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:15.000+0100', 2),
    (log_parser.ip_to_int('5.6.7.8'), '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:22.000+0100', 30),
    (log_parser.ip_to_int('9.10.11.12'), '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:13.000+0100', 4),
]
ip_processed_data = [
    (log_parser.ip_to_int("1.2.3.4"), 1024, 'some-log-file.log')
]


def test_path_based_judgment_block():
    bot_path = {"/phpMyAdmin/", "/pma/", "/myadmin", "/MyAdmin/", "/wp-login", "/webdav/", "/manager/html"}
    blocker = judgment.PathBasedIpJudgment(bot_path)
    entry = log_parser.LogEntry(
        "dummy-log.txt",
        1234,
        ip=log_parser.ip_to_int('111.21.253.2'),
        time=datetime.strptime("2019-03-28 11:15:33.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        request="GET /manager/html",
        byte=4286
    )
    (block, cause) = blocker.should_deny(entry)
    assert block == True
    assert cause is not None


def test_path_based_judgment_free():
    bot_path = {"/phpMyAdmin/", "/pma/", "/myadmin", "/MyAdmin/", "/wp-login", "/webdav/", "/manager/html"}
    blocker = judgment.PathBasedIpJudgment(bot_path)
    entry = log_parser.LogEntry(
        "dummy-log.txt",
        1234,
        ip=log_parser.ip_to_int('111.21.253.2'),
        time=datetime.strptime("2019-03-28 11:15:33.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        request="GET /test",
        byte=4286
    )
    (block, cause) = blocker.should_deny(entry)
    assert not block


def test_time_based_judgment__ready_processed():
    global test_db_path
    processed_ip = ip_processed_data[0]
    log_entry = log_parser.LogEntry(
        processed_ip[2],
        processed_ip[1],
        ip=processed_ip[0],
        time=datetime.strptime("2019-03-28 11:12:30.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        byte=4286
    )
    conn = sqlite3.connect(test_db_path)
    with conn:
        blocker = judgment.TimeBasedIpJudgment(test_db_path)
        is_processed = blocker._ready_processed(log_entry)
        assert is_processed is True
    conn.close()


from importlib_resources import read_text
@pytest.fixture
def _prepare_test_data(caplog):
    global test_db_path
    print("**********************")
    caplog.set_level(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)

    conn = sqlite3.connect(test_db_path)
    with conn:
        sql_script = read_text("find2deny", "log-data.sql")
        sql_code = '''\n
        DROP TABLE IF EXISTS log_ip;
        DROP TABLE IF EXISTS block_network;
        DROP TABLE IF EXISTS processed_log_ip;
        VACUUM;
        ''' + sql_script
        conn.executescript(sql_code)
    conn.close()
    # judgment.init_database(test_db_path)

    conn = sqlite3.connect(test_db_path)
    with conn:
        conn.executemany("INSERT INTO log_ip (ip, first_access, last_access, access_count) VALUES (?, ? , ?, ?)", ip_data)
        conn.executemany("INSERT INTO processed_log_ip (ip, line, log_file) VALUES (?, ?, ?)", ip_processed_data)
    conn.close()
    print("**********************init database done")


def test_update_deny(_prepare_test_data):
    global test_db_path
    ip_network = "123.456.789.321/22"
    log_entry = log_parser.LogEntry(
        "some-log-file.log",
        2,
        ip=log_parser.ip_to_int("1.2.3.4"),
        time=datetime.strptime("2019-03-28 11:15:33.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        request="GET /manager/html",
        byte=4286
    )
    judge = "judge of party"
    cause = "just for fun"
    judgment.update_deny(ip_network, log_entry, judge, cause, test_db_path)
    conn = sqlite3.connect(test_db_path)
    c = conn.cursor()
    c.execute("SELECT COUNT(*), cause_of_block FROM block_network WHERE ip = ?", (log_entry.ip,))
    row = c.fetchone()
    ip_count = row[0]
    cause_of_block = row[1]
    assert ip_count == 1
    assert cause_of_block == cause


def test_time_based_judgment_should_deny__add_new_entry_to_log(_prepare_test_data):
    global test_db_path
    ip = log_parser.ip_to_int('8.7.6.5')
    line = 512
    log_file = "some-log-file.log"
    log_entry = log_parser.LogEntry(
        log_file,
        line,
        ip=ip,
        time=datetime.strptime("2019-03-28 11:12:30.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        byte=4286
    )
    conn = sqlite3.connect(test_db_path)
    with conn:
        blocker = judgment.TimeBasedIpJudgment(conn)
        to_be_deny, cause = blocker.should_deny(log_entry)
        assert to_be_deny is False

        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM log_ip WHERE ip = ?", (ip,))
        row = c.fetchone()
        ip_count = row[0]
        assert ip_count == 1
        c.execute("SELECT COUNT(*) FROM processed_log_ip WHERE ip = ? AND line = ? AND log_file = ?",
                  (ip, line, log_file))
        row2 = c.fetchone()
        ip_count = row2[0]
        assert ip_count == 1
    conn.close()


def test_time_based_judgment_block_ip_network(_prepare_test_data):
    global test_db_path

    ip = log_parser.ip_to_int('5.6.7.8')
    log_entry = log_parser.LogEntry(
        "some-log-file.log",
        2,
        ip=ip,
        time=datetime.strptime("2019-03-28 11:12:23.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        byte=4286
    )
    conn = sqlite3.connect(test_db_path)
    with conn:
        blocker = judgment.TimeBasedIpJudgment(test_db_path)
        to_be_deny, cause = blocker.should_deny(log_entry)
        assert to_be_deny is True
        c = conn.cursor()
        c.execute("SELECT status FROM log_ip WHERE ip = ?", (ip,))
        row = c.fetchone()
        ip_count = row[0]
        assert ip_count == 1
    conn.close()


def test_time_based_judgment_update_access_time(_prepare_test_data):
    global test_db_path
    ip = log_parser.ip_to_int('9.10.11.12')
    log_entry = log_parser.LogEntry(
        "some-log-file.log",
        2,
        ip=ip,
        time=datetime.strptime("2019-03-28 11:15:33.000+0100",
                               judgment.DATETIME_FORMAT_PATTERN),
        status=401,
        byte=4286
    )
    conn = sqlite3.connect(test_db_path)
    with conn:
        blocker = judgment.TimeBasedIpJudgment(test_db_path)
        to_be_deny, cause = blocker.should_deny(log_entry)
        assert to_be_deny == False
        c = conn.cursor()
        c.execute("SELECT access_count FROM log_ip WHERE ip = ?", (ip,))
        row = c.fetchone()
        ip_count = row[0]
        assert ip_count == 5
    conn.close()


def test_user_agent_based_judgment():
    ip = log_parser.ip_to_int('9.10.11.12')
    log_entry = log_parser.LogEntry(
        "some-log-file.log",
        2,
        ip=ip,
        user_agent="Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)"
    )
    blacklist_agent = ['http://ahrefs.com/robot', 'http://www.semrush.com/bot.html']
    blocker = judgment.UserAgentBasedIpJudgment(blacklist_agent)
    deny, cause = blocker.should_deny(log_entry)
    assert deny is True


def test_user_agent_based_judgment_2():
    ip = log_parser.ip_to_int('54.36.150.103')
    log_entry = log_parser.LogEntry(
        "some-log-file.log",
        2,
        ip=ip,
        user_agent="Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)"
    )
    blacklist_agent = ['http://ahrefs.com', 'http://www.semrush.com']
    blocker = judgment.UserAgentBasedIpJudgment(blacklist_agent)
    deny, cause = blocker.should_deny(log_entry)
    assert deny is True


def test_lookup():
    ip = "134.96.210.150"
    expected_network = "134.96.0.0/16"
    first_lookup_start = time.perf_counter()
    network = judgment.lookup_ip(ip)
    first_lookup_stop = time.perf_counter()
    first_lookup_duration = first_lookup_stop - first_lookup_start
    logging.info("Lookup time: %s", first_lookup_duration)
    assert network == expected_network

    cache_lookup_start = time.perf_counter()
    network_cache = judgment.lookup_ip(log_parser.ip_to_int(ip))
    cache_lookup_stop = time.perf_counter()
    cache_lookup_duration = cache_lookup_stop - cache_lookup_start
    logging.info("Caching time: %s", cache_lookup_duration)
    assert network_cache == expected_network

    assert cache_lookup_duration <= first_lookup_duration


def test_lookup_2():
    ip = "54.36.148.129"
    expected_network = "54.36.148.0/22 54.36.0.0/16"
    first_lookup_start = time.perf_counter()
    network = judgment.lookup_ip(ip)
    first_lookup_stop = time.perf_counter()
    first_lookup_duration = first_lookup_stop - first_lookup_start
    logging.info("Lookup time: %s", first_lookup_duration)
    assert network == expected_network


def test_white_list():
    ip = "34.96.214.15"
    white_list_fn = judgment.make_ip_check_fn(ip)
    white_list = []
    assert next((item for item in white_list if white_list_fn(item)), None) is None


def test_white_list_no_match():
    ip = "34.96.214.15"
    white_list_fn = judgment.make_ip_check_fn(ip)
    white_list = ["134.95.96.7", "134.95.96.9"]
    assert next((item for item in white_list if white_list_fn(item)), None) is None


def test_white_list_equal():
    ip = "134.96.214.15"
    white_list_fn = judgment.make_ip_check_fn(ip)
    white_list = ["134.96.214.15"]
    assert next((item for item in white_list if white_list_fn(item)), None) == white_list[0]


def test_white_list_subnet():
    ip = "134.96.214.15"
    white_list_fn = judgment.make_ip_check_fn(ip)
    white_list = ["134.96.0.0/16"]
    assert next((item for item in white_list if white_list_fn(item)), None) == white_list[0]


def test_white_list_reg():
    ip = "134.96.214.15"
    white_list_fn = judgment.make_ip_check_fn(ip)
    white_list = [r"134\.96\.\d+\.\d+"]
    assert next((item for item in white_list if white_list_fn(item)), None) == white_list[0]