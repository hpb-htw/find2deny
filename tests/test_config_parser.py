from find2deny import config_parser

import pprint


def test_parse_config_file():
    test_config_file = "test-data/rules.toml"
    config = config_parser.parse_config_file(test_config_file)
    print("\n")
    pprint.pprint(config)