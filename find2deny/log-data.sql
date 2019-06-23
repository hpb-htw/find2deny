CREATE TABLE IF NOT EXISTS block_network (
    ip INTEGER PRIMARY KEY,
    ip_network TEXT ,
    block_since TEXT,
    judge TEXT default  NULL,
    cause_of_block TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS log_ip (
    ip INTEGER PRIMARY KEY,
    ip_network TEXT DEFAULT NULL ,
    first_access TEXT,
    last_access TEXT,
    access_count INTEGER,
    status INTEGER DEFAULT 0
);
/*
status: 0 => allow
        1 => block
*/

CREATE TABLE IF NOT EXISTS processed_log_ip (
    ip INTEGER,
    line INTEGER,
    log_file TEXT,
    PRIMARY KEY (ip,line, log_file)
);

/*                         processed_log_file */
CREATE TABLE IF NOT EXISTS processed_log_file (
    content_hash TEXT PRIMARY KEY,
    path TEXT
);