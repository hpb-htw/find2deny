# Usage


`find2deny-cli <config-file.cfg>`

`config-file` a file which https://docs.python.org/3/library/configparser.html
can parse. Example

```ini
[DEFAULT]
log_files=<list of log file, separated by space>
log_pattern=<log-pattern>

[judgment]
judgments_chain=<name of judgments>
bot-request=<request paths that like from a bot, separated by space>
max-request=10
interval-seconds=10
time-database-path=<path to a sqlite database>
``` 


## Log Pattern

## Judgment Chain (`judgments_chain`)

A list of judgment names. A log entry is checked by all judgments in the chain, as long as its IP is classified as 
bot by one of judgment in the chain or the last Judgment in the chain does not classify it as bot. So the order
of the Judgment is significant.

Implemented Judgments (for now) are:

### Path based Judgment

* name: 'path-based-judgment'
* description: an IP in a log entry is as a bot classified when it hast a request that begins
  with one of the list in config `judgment.bot-request`

### Time based Judgment

* name: 'time-based-judgment'
* description: an IP in a log entry is as a bot classified when it make more than `judgment.max-request` HTTP-request
in a given (`judgment.interval-second`) in seconds. To calculate the time interval from the first recognized request
to last request of the IP in the log files, this judgment use a SQLite file which is configured by `time-database-path`
This file is automatically created if it does not exist.