package dbbackup

import (
	"database/sql"
	"os"
	"path/filepath"
)

// Create captures SQLite's committed state, including WAL, without copying live files.
func Create(db *sql.DB, path string, key []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".pre-upgrade-*.db")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err = f.Close(); err != nil {
		return "", err
	}
	if _, err = db.Exec("VACUUM INTO ?", name); err != nil {
		os.Remove(name)
		return "", err
	}
	if len(key) != 0 {
		if err = os.WriteFile(name+".key", key, 0600); err != nil {
			return "", err
		}
	}
	return name, nil
}
