CREATE TABLE users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username VARCHAR(100) UNIQUE NOT NULL,
 password VARCHAR(255) NOT NULL,
 role VARCHAR(20) NOT NULL DEFAULT 'user'
);
-- The Flask app automatically creates the remaining tables.
-- For a MySQL conversion, change SQLite INTEGER/TIMESTAMP syntax as needed.
