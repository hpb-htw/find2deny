#!/usr/bin/python3


from datetime import datetime
import pytest
import logging
from .context import ip_grep
import sqlite3

test_db_path = './test-data/ipdb.sqlite'


@pytest.fixture
def prepare_test_data(caplog):
    global test_db_path
    caplog.set_level(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)
    conn = sqlite3.connect(test_db_path)
    with open("log-data.sql") as sql_file:
        sql_code = sql_file.read()
        conn.executescript(sql_code)

    ip_data = [
        (ip_grep.LogEntry.ip_to_int('1.2.3.4'),    '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:15.000+0100', 2),
        (ip_grep.LogEntry.ip_to_int('5.6.7.8'),    '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:23.000+0100', 30),
        (ip_grep.LogEntry.ip_to_int('9.10.11.12'), '2019-03-28 11:12:13.000+0100', '2019-03-28 11:12:13.000+0100', 4),
    ]
    conn.executemany("INSERT INTO log_ip (ip, first_access, last_access, access_count) VALUES (?, ? , ?, ?)", ip_data)
    conn.commit()
    conn.close()
    print("init database done")


def test_should_deny__add_new_entry_to_log(prepare_test_data, caplog):
    global test_db_path

    blocker = ip_grep.TimeBasedIpBlocker(test_db_path)
    ip = ip_grep.LogEntry.ip_to_int('8.7.6.5')
    log_entry = ip_grep.LogEntry(
        ip=ip,
        time=datetime.strptime("2019-03-28 11:12:30.000+0100",
                               ip_grep.SQL_LITE_DATETIME_PATTERN),
        status=401,
        byte=4286
    )
    to_be_deny = blocker.should_deny(log_entry)
    assert to_be_deny == False
    conn = sqlite3.connect(test_db_path)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM log_ip WHERE ip = ?", (ip,))
    row = c.fetchone()
    ip_count = row[0]
    assert ip_count == 1


def test_block_ip_network(prepare_test_data):
    global test_db_path
    blocker = ip_grep.TimeBasedIpBlocker(test_db_path)
    ip = ip_grep.LogEntry.ip_to_int('5.6.7.8')
    log_entry = ip_grep.LogEntry(
        ip=ip,
        time=datetime.strptime("2019-03-28 11:12:33.000+0100",
                               ip_grep.SQL_LITE_DATETIME_PATTERN),
        status=401,
        byte=4286
    )
    to_be_deny = blocker.should_deny(log_entry)
    assert to_be_deny == True
    conn = sqlite3.connect(test_db_path)
    c = conn.cursor()
    c.execute("SELECT status FROM log_ip WHERE ip = ?", (ip,))
    row = c.fetchone()
    ip_count = row[0]
    assert ip_count == 1


def test_update_access_time():
    global test_db_path
    blocker = ip_grep.TimeBasedIpBlocker(test_db_path)
    ip = ip_grep.LogEntry.ip_to_int('9.10.11.12')
    log_entry = ip_grep.LogEntry(
        ip=ip,
        time=datetime.strptime("2019-03-28 11:15:33.000+0100",
                               ip_grep.SQL_LITE_DATETIME_PATTERN),
        status=401,
        byte=4286
    )
    to_be_deny = blocker.should_deny(log_entry)
    assert to_be_deny == False
    conn = sqlite3.connect(test_db_path)
    c = conn.cursor()
    c.execute("SELECT access_count FROM log_ip WHERE ip = ?", (ip,))
    row = c.fetchone()
    ip_count = row[0]
    assert ip_count == 5