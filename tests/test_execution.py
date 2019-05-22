import pytest

from find2deny import execution, log_parser



ufw_script="block-ip.sh"

@pytest.fixture
def clean_output_file():
    with open(ufw_script, 'w') as f:
        f.write('')
    pass


def test_FileBasedUFWBlock(clean_output_file):
    log = [log_parser.LogEntry(
        "some-file",
        1234,
        ip=log_parser.ip_to_int("1.2.3.4"),
        network="1.2.3.4/"+str(x),
        time=None,
        status=404,
        request="GET /abcd",
        byte=1024,
        user=None
    )for x in range(10)]
    blocker = execution.FileBasedUWFBlock(ufw_script)
    blocker.begin_execute()
    for l in log:
        blocker.block(l)
    blocker.end_execute()
    pass