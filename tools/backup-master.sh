#!/bin/sh
# Offline only: stop the selected role and prevent concurrent filesystem changes.
# Python 3 stdlib only. No database is opened. Only new destinations are accepted.
# Copies retain numeric uid/gid (run as the owner or root); dirs/files become 0700/0600.
set -eu
umask 077
exec python3 - "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def require(ok):
    if not ok:
        raise ValueError("invalid backup or unsafe filesystem")


def plain_path(arg):
    p = Path(os.path.abspath(arg))
    # Parent links such as macOS /var are trusted; tree entries are lstat'ed.
    require(not p.is_symlink())
    return Path(os.path.realpath(p))


def inventory(root):
    result = {}

    def visit(path, relative):
        info = path.lstat()
        record = {"uid": info.st_uid, "gid": info.st_gid}
        if stat.S_ISDIR(info.st_mode):
            record["type"] = "directory"
            result[relative] = record
            for child in sorted(path.iterdir()):
                visit(child, child.relative_to(root).as_posix())
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            record["type"] = "file"
            with path.open("rb") as stream:
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            record["sha256"] = digest.hexdigest()
            result[relative] = record
    require(root.is_dir())
    visit(root, ".")
    return result


def validate_role(entries, role):
    files = {name for name, entry in entries.items() if entry["type"] == "file"}
    require(bool(files))
    if role == "master":
        require({"veilink.db", "veilink.key"} <= files)
    else:
        # StateDir may be /data itself or any nested/hidden directory below it.
        require(any(Path(name).name == "state.json" for name in files))
        require("veilink.db" not in files and "veilink.key" not in files)


def secure_copy(source, target, entries):
    shutil.copytree(source, target)
    # Children first so directory ownership changes cannot block the copy.
    for name, entry in sorted(entries.items(), reverse=True):
        path = target if name == "." else target / name
        info = path.lstat()
        if (info.st_uid, info.st_gid) != (entry["uid"], entry["gid"]):
            os.chown(path, entry["uid"], entry["gid"])
        os.chmod(path, 0o700 if entry["type"] == "directory" else 0o600)
    require(inventory(target) == entries)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def main():
    if len(sys.argv) != 5 or sys.argv[1] not in ("backup", "restore") or sys.argv[2] not in ("master", "node"):
        print("usage: backup-master.sh backup|restore master|node <source-dir> <new-destination-dir>", file=sys.stderr)
        return 2
    action, role = sys.argv[1:3]
    source, dest = map(plain_path, sys.argv[3:])
    require(source.is_dir() and not dest.exists() and dest.parent.is_dir())
    require(source != dest and source not in dest.parents and dest not in source.parents)
    if action == "backup":
        data = source
        entries = inventory(data)
    else:
        require({p.name for p in source.iterdir()} == {"data", "manifest.json"})
        require(stat.S_ISREG((source / "manifest.json").lstat().st_mode))
        with (source / "manifest.json").open() as stream:
            manifest = json.load(stream, object_pairs_hook=unique_object)
        require(set(manifest) == {"version", "role", "entries"})
        require(manifest["version"] == 1 and manifest["role"] == role)
        data = source / "data"
        entries = inventory(data)
        # Exact equality checks every directory/file and rejects omitted, extra,
        # duplicate, traversal and absolute names without ever following them.
        require(manifest["entries"] == entries)
    validate_role(entries, role)
    stage = Path(tempfile.mkdtemp(prefix=".veilink-backup-", dir=dest.parent))
    reserved = False
    try:
        copied = stage / "data"
        secure_copy(data, copied, entries)
        require(inventory(data) == entries)
        if action == "backup":
            with (stage / "manifest.json").open("x") as stream:
                json.dump({"version": 1, "role": role, "entries": entries}, stream, sort_keys=True)
            publish = stage
        else:
            publish = copied
        # Publish only after the copied tree and manifest have been verified.
        os.rename(publish, dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print(action + " complete")
    return 0


try:
    sys.exit(main())
except (Exception, KeyboardInterrupt):
    # Never log paths, manifest contents, credentials, or raw exception messages.
    print("backup/restore failed; check offline source, manifest, ownership and destination", file=sys.stderr)
    sys.exit(1)
PY
