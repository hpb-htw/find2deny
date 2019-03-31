DROP TABLE IF EXISTS log_ip;
DROP TABLE IF EXISTS block_network;


CREATE TABLE block_network (
    ip_network TEXT PRIMARY KEY,
    block_since TEXT      /* ISO8601 Format */
);

CREATE TABLE log_ip (
    ip INTEGER PRIMARY KEY,
    ip_network DEFAULT NULL REFERENCES block_network(ip_network) ,
    first_access TEXT,     /* ISO8601 Format */
    last_access TEXT,      /* ISO8601 Format */
    access_count INTEGER,
    status INTEGER DEFAULT 0
);
/*
status: 0 => allow
        1 => block
*/
