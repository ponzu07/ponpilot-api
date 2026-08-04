CREATE TABLE users (
  id         INTEGER PRIMARY KEY,
  identity   TEXT NOT NULL UNIQUE,
  username   TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
