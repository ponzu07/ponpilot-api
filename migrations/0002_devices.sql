CREATE TABLE devices (
  dongle_id        TEXT PRIMARY KEY,
  public_key       TEXT NOT NULL,
  owner_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
  last_athena_ping INTEGER
);
