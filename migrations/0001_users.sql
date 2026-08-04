CREATE TABLE users (
  id         INTEGER PRIMARY KEY,
  identity   TEXT NOT NULL UNIQUE,
  username   TEXT,
  created_at INTEGER NOT NULL
);
