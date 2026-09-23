CREATE TABLE IF NOT EXISTS config (
 id INTEGER PRIMARY KEY CHECK(id=1),
 data BLOB NOT NULL CHECK(json_valid(data))
);
CREATE TABLE IF NOT EXISTS admin(username TEXT PRIMARY KEY, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS credentials(node TEXT PRIMARY KEY, hash TEXT NOT NULL CHECK(length(hash)=64));
CREATE TABLE IF NOT EXISTS enroll(node TEXT PRIMARY KEY, hash TEXT NOT NULL CHECK(length(hash)=64), expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(at INTEGER NOT NULL, action TEXT NOT NULL, object TEXT NOT NULL);
-- Configuration is a single transactional aggregate, with DB-level checks in
-- addition to Go validation. Never store plaintext binding UUIDs in the aggregate.
CREATE TRIGGER IF NOT EXISTS config_validate BEFORE UPDATE ON config BEGIN
 SELECT CASE WHEN EXISTS (
  SELECT 1 FROM json_each(NEW.data,'$.Bindings') b
  WHERE json_extract(b.value,'$.uuid') IS NOT NULL
   OR NOT EXISTS (SELECT 1 FROM json_each(NEW.data,'$.Nodes') n WHERE n.key=json_extract(b.value,'$.server_id') AND json_extract(n.value,'$.role')='server')
   OR NOT EXISTS (SELECT 1 FROM json_each(NEW.data,'$.Nodes') n WHERE n.key=json_extract(b.value,'$.client_id') AND json_extract(n.value,'$.role')='client')
 ) THEN RAISE(ABORT,'invalid binding') END;
 SELECT CASE WHEN EXISTS (
  SELECT 1 FROM json_each(NEW.data,'$.Mappings') m
  WHERE json_extract(m.value,'$.listen_port') NOT BETWEEN 1 AND 65535
   OR json_extract(m.value,'$.target_port') NOT BETWEEN 1 AND 65535
   OR NOT EXISTS (SELECT 1 FROM json_each(NEW.data,'$.Bindings') b WHERE b.key=json_extract(m.value,'$.binding_id'))
 ) THEN RAISE(ABORT,'invalid mapping') END;
 SELECT CASE WHEN EXISTS (
  SELECT 1 FROM json_each(NEW.data,'$.Mappings') a
  JOIN json_each(NEW.data,'$.Mappings') b ON a.key<b.key
  JOIN json_each(NEW.data,'$.Bindings') ba ON ba.key=json_extract(a.value,'$.binding_id')
  JOIN json_each(NEW.data,'$.Bindings') bb ON bb.key=json_extract(b.value,'$.binding_id')
  WHERE json_extract(a.value,'$.enabled')=1 AND json_extract(b.value,'$.enabled')=1
   AND json_extract(ba.value,'$.server_id')=json_extract(bb.value,'$.server_id')
   AND json_extract(a.value,'$.listen_port')=json_extract(b.value,'$.listen_port')
   AND (json_extract(a.value,'$.listen_host')=json_extract(b.value,'$.listen_host')
    OR json_extract(a.value,'$.listen_host') IN ('0.0.0.0','::','')
    OR json_extract(b.value,'$.listen_host') IN ('0.0.0.0','::',''))
 ) THEN RAISE(ABORT,'mapping port conflict') END;
END;
