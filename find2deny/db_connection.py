# -*- encoding: utf8 -*-


import sqlite3


def get_connection(sqlite_db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(sqlite_db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

