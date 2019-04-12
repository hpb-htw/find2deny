import pprint

from find2deny import cli


def test_parse_argv():
    argv = ["--verbosity", "DEBUG", "test-data/rules.cfg"]
    cli_config = cli.parse_arg(argv)
    effective_config = cli.merge_config(cli_config)

    assert effective_config["verbosity"] == "DEBUG"
    assert effective_config["log_files"][0] == "test-data/apache2/access.log.8"
    assert effective_config["log_pattern"] == '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
    assert effective_config["judgments_chain"] == ["path-based-judgment", "time-based-judgment"]
    assert len(effective_config["bot_request"]) >= 14
    assert effective_config["max_request"] == 501
    assert effective_config["interval_seconds"] == 59


def test_parse_argv_no_option():
    argv = ["test-data/rules.cfg"]
    cli_config = cli.parse_arg(argv)
    effective_config = cli.merge_config(cli_config)
    assert effective_config["verbosity"] == "INFO"
    assert effective_config["log_files"][0] == "test-data/apache2/access.log.8"
    assert effective_config["log_pattern"] == '%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"'
    assert effective_config["judgments_chain"] == ["path-based-judgment", "time-based-judgment"]
    assert len(effective_config["bot_request"]) >= 14
    assert effective_config["max_request"] == 501
    assert effective_config["interval_seconds"] == 59


def test_expand_logfiles():
    blob_logs = ["test-data/apache2/*.gz"]
    log_files = cli.expand_log_files(blob_logs)
    assert len(log_files) > 1


def test_construct_judgment():
    config = {"bot_request":["/phpmyadmin.php"]}
    name = "path-based-judgment"
    judgment = cli.judgment_by_name(name, config)
