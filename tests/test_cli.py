import pytest
import logging
import sqlite3

from find2deny import cli
from find2deny import judgment


def test_expand_logfiles():
    blob_logs = ["test-data/apache2-markov/access.log*"]
    log_files = cli.expand_log_files(blob_logs)
    print(log_files)
    assert len(log_files) == 15


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


test_db_path = './test-data/ipdb.sqlite'
file_processed_data = [
    ("1111","test-data/apache2-markov/access.log.2.gz"),
    ("2222","test-data/apache2-markov/access.log.3.gz")
    # test-data/apache2-markov/access.log.2.gz
]


from importlib_resources import read_text
@pytest.fixture
def prepare_test_data(caplog):
    global test_db_path
    print("**********************")
    caplog.set_level(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)

    conn = sqlite3.connect(test_db_path)
    with conn:
        sql_script = read_text("find2deny", "log-data.sql")
        sql_code = '''
        DROP TABLE IF EXISTS processed_log_file;       
        ''' + sql_script
        conn.executescript(sql_code)
        conn.commit()
    conn.close()
    # judgment.init_database(test_db_path)
    conn = sqlite3.connect(test_db_path)
    with conn:
        conn.executemany("INSERT INTO processed_log_file(content_hash, path) VALUES (?, ?)", file_processed_data)
    conn.close()
    print("**********************init database done")


def test_expand_logfiles_with_cached(prepare_test_data):
    blob_logs = ["test-data/apache2-markov/access.log*"]
    log_files = cli.expand_log_files(blob_logs)
    print(log_files)
    assert len(log_files) == 15


def test_update_not_yet_processed_file(prepare_test_data):
    hash_content = "3333"
    file_path = "test-data/some-dir/some-file.tar.gz"
    conn = sqlite3.connect(test_db_path)
    with conn:
        cli.update_processed_file(hash_content, file_path, conn)
        c = conn.cursor()
        c.execute("SELECT path FROM processed_log_file WHERE content_hash = ?", (hash_content,))
        expected_file_path = c.fetchone()[0]
    conn.close()
    assert expected_file_path == file_path


def test_update_ready_inserted_processed_file(prepare_test_data):
    hash_content = "3333"
    file_path = file_processed_data[1][1]  # change hash_content of file_path to 3333, distinct from ready inserted file
    conn = sqlite3.connect(test_db_path)
    with conn:
        cli.update_processed_file(hash_content, file_path, conn)
        c = conn.cursor()
        c.execute("SELECT path FROM processed_log_file WHERE content_hash = ?", (hash_content,))
        expected_file_path = c.fetchone()[0]
    conn.close()
    assert expected_file_path == file_path
    pass


def test_update_ready_inserted_processed_file_2(prepare_test_data):
    hash_content = "2222" # change file_path of given hash_content
    file_path = "test-data/some-dir/some-file.tar.gz"
    conn = sqlite3.connect(test_db_path)
    with conn:
        cli.update_processed_file(hash_content, file_path, conn)
        c = conn.cursor()
        c.execute("SELECT path FROM processed_log_file WHERE content_hash = ?", (hash_content,))
        expected_file_path = c.fetchone()[0]
    conn.close()
    assert expected_file_path == file_path
    pass