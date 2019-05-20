import pprint

from find2deny import cli



def test_expand_logfiles():
    blob_logs = ["test-data/apache2/*.gz"]
    log_files = cli.expand_log_files(blob_logs)
    assert len(log_files) > 1


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



