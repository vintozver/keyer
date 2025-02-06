# -*- coding: utf-8 -*-

import sqlite3
log_access_create = """
CREATE TABLE access_log (
    dt INT NOT NULL PRIMARY KEY,
    hash VARCHAR(32) NOT NULL,
    name VARCHAR(64),
    email VARCHAR(128),
    description VARCHAR(4),
    flags VARCHAR(16),
    action VARCHAR(16) NOT NULL,
    result VARCHAR(16) NOT NULL
)
"""

log_access_insert = """ 
INSERT INTO access_log
(dt, hash, name, email, description, flags, action, result)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""

log_access_select = """
SELECT dt, hash, name, email, description, flags, action, result
FROM access_log
WHERE dt < ?
"""

