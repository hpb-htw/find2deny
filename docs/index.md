# Usage


`find2deny-cli <config-file.toml>`

`config-file` a file which https://docs.python.org/3/library/configparser.html
can parse. Example

```toml
TODO!
``` 


## Log Pattern (`log_pattern`)

TODO!

## Judgment Chain (`judgments_chain`)

A list of judgment names. A log entry is checked by all judgments in the chain, as long as its IP is classified as 
bot by one of judgment in the chain or the last Judgment in the chain does not classify it as bot. So the order
of the Judgment is significant.

Implemented Judgments (for now) are:

### Path based Judgment (`path-based-judgment`)

An IP in a log entry is as a bot classified when it hast a request that begins
with one of the list in config `judgment/bot-request`

### Time based Judgment (`time-based-judgment`)


an IP in a log entry is as a bot classified when it make more than `judgment.max-request` HTTP-request
in a given (`judgment/interval-second`) in seconds. To calculate the time interval from the first recognized request
to last request of the IP in the log files, this judgment use a SQLite file which is configured by `time-database-path`
This file is automatically created if it does not exist.