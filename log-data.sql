/*
DROP TABLE IF EXISTS log_ip;
DROP TABLE IF EXISTS block_network;
*/

CREATE TABLE IF NOT EXISTS block_network (
    ip_network TEXT PRIMARY KEY,
    block_since TEXT
);

CREATE TABLE IF NOT EXISTS log_ip (
    ip INTEGER PRIMARY KEY,
    ip_network DEFAULT NULL REFERENCES block_network(ip_network) ,
    first_access TEXT,
    last_access TEXT,
    access_count INTEGER,
    status INTEGER DEFAULT 0
);
/*
status: 0 => allow
        1 => block
*/
