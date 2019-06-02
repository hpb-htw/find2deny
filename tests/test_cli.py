import pytest
import logging
import sqlite3

from find2deny import cli
from find2deny import judgment

test_db_path = './test-data/ipdb.sqlite'
file_processed_data = [
    ("test-data/apache2-markov/access.log.2.gz",)
    # test-data/apache2-markov/access.log.2.gz
]

@pytest.fixture
def prepare_test_data(caplog):
    global test_db_path
    print("**********************")
    caplog.set_level(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)

    conn = sqlite3.connect(test_db_path)
    with conn:
        sql_code = '''
        DROP TABLE IF EXISTS processed_log_file;       
        '''
        conn.executescript(sql_code)

    judgment.init_database(test_db_path)

    with sqlite3.connect(test_db_path) as conn:
        conn.executemany("INSERT INTO processed_log_file(log_file) VALUES (?)", file_processed_data)
        conn.commit()
    print("**********************init database done")


def test_expand_logfiles():
    blob_logs = ["test-data/apache2-markov/access.log*"]
    log_files = cli.expand_log_files(blob_logs)
    print(log_files)
    assert len(log_files) == 15


def test_expand_logfiles_with_cached(prepare_test_data):
    blob_logs = ["test-data/apache2-markov/access.log*"]
    log_files = cli.expand_log_files(blob_logs, database_path=test_db_path)
    print(log_files)
    assert len(log_files) == 14


def test_construct_judgment():
    judge = {
        "name": "path-based-judgment",
        "rules": {
            "bot_request":[
                "/phpMyAdmin.php",
            ]
        }
    }
    judgment = cli.judgment_by_name(judge, None)
    assert str(judgment).count("/phpMyAdmin.php") >= 1


def test_apache_access_log_file_chronological_decode():
    file_name = "dummy/access.log"
    assert cli.apache_access_log_file_chronological_decode(file_name) == 0


def test_apache_access_log_file_chronological_decode_1():
    file_name = "dummy/access.log.1"
    assert cli.apache_access_log_file_chronological_decode(file_name) == -1


def test_apache_access_log_file_chronological_decode_2():
    file_name = "dummy/access.log.10.gz"
    assert cli.apache_access_log_file_chronological_decode(file_name) == -10
