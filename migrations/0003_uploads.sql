CREATE TABLE uploads (
  dongle_id  TEXT NOT NULL REFERENCES devices(dongle_id) ON DELETE CASCADE,
  route_name TEXT NOT NULL,
  segment    INTEGER NOT NULL,
  filename   TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (dongle_id, route_name, segment, filename)
);
