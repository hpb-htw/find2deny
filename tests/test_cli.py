import pprint

from find2deny import cli


def test_parse_argv():
    argv = ["--verbosity", "DEBUG", "test-data/rules.cfg"]
    cli.do_the_job(argv)
    assert cli.effective_config["verbosity"] == "DEBUG"
    assert cli.effective_config["log_files"][0] == "test_data/apache2/access.log.8"
    assert cli.effective_config["log_pattern"] == '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
    assert cli.effective_config["judgments_chain"] == ["path-based-judgment", "time-based-judgment"]
    assert len(cli.effective_config["bot_request"]) == 14
    assert cli.effective_config["max_request"] == 501
    assert cli.effective_config["interval_seconds"] == 59


def test_parse_argv_no_option():
    argv = ["test-data/rules.cfg"]
    cli.do_the_job(argv)

'''
def test_help():
    argv = ["-h"]
    cli.do_the_job(argv)
'''

def test_expand_logfiles():
    config = {cli.LOG_FILES: ["test-data/apache2/*.gz"]}
    log_files = cli.expand_log_files(config)
    assert len(log_files) > 1


def test_construct_judgment():
    config = {"bot_request":["/phpmyadmin.php"]}
    name = "path-based-judgment"
    judgment = cli.judgment_by_name(name, config)
