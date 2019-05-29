import pprint

from find2deny import cli


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
