CREATE TABLE athena_queue (
  id        INTEGER PRIMARY KEY,
  dongle_id TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  method    TEXT NOT NULL,
  params    TEXT NOT NULL,
  expiry    INTEGER NOT NULL
);
