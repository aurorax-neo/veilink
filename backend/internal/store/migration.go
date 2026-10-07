package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"veilink/internal/auth"
	"veilink/internal/config"
	"veilink/internal/dbbackup"
	"veilink/internal/model"
)

func migratePreviousRelease(db *sql.DB, path string, key []byte) error {
	var version int
	if err := db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil {
		return err
	}
	if version == schemaVersion {
		return nil
	}
	if version != 5 {
		return errors.New("unsupported database migration")
	}
	var previous []byte
	if err := db.QueryRow("SELECT data FROM config WHERE id=1").Scan(&previous); err != nil {
		return err
	}
	var st state
	d := json.NewDecoder(bytes.NewReader(previous))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("invalid persisted configuration")
	}
	if st.Revision < 0 || st.Nodes == nil || st.Bindings == nil || st.Mappings == nil || st.Secrets == nil {
		return errors.New("incomplete persisted configuration")
	}
	before := cloneState(st)
	for id, node := range st.Nodes {
		if node.ID != id {
			return ErrInvalid
		}
		if node.Role == "server" {
			candidate := node
			candidate.ClientTunnel = nil
			paired, err := clientTemplate(candidate)
			if err != nil {
				return fmt.Errorf("cannot migrate server %q: %w", id, err)
			}
			// v0.4.2 stored packed ML-DSA keys without deriving the public key.
			if node.ClientTunnel != nil && paired != nil && *node.ClientTunnel != *paired {
				legacy := *paired
				legacy.Reality.Mldsa65Verify = ""
				if node.Tunnel.Reality.Mldsa65Seed == "" || node.Tunnel.Reality.Mldsa65Verify != "" || *node.ClientTunnel != legacy {
					return fmt.Errorf("cannot migrate custom client_tunnel for server %q: %w", id, ErrInvalid)
				}
			}
			if node.ClientTunnel != nil && paired == nil {
				return ErrInvalid
			}
			node.ClientTunnel = paired
		} else if node.Role != "client" || node.ClientTunnel != nil || node.Tunnel != (model.LocalTLS{}) {
			return ErrInvalid
		}
		st.Nodes[id] = node
	}
	for id, sealed := range st.Secrets {
		if _, err := auth.Open(key, sealed); err != nil {
			return fmt.Errorf("cannot decrypt existing secret %q; restore the original deployment key: %w", id, err)
		}
	}
	for id, binding := range st.Bindings {
		if binding.ID != id || binding.UUID != "" || st.Nodes[binding.ServerID].Role != "server" || st.Nodes[binding.ClientID].Role != "client" {
			return ErrInvalid
		}
		if _, err := auth.Open(key, st.Secrets[id]); err != nil {
			return fmt.Errorf("missing or corrupt binding secret %q: %w", id, err)
		}
	}
	for id, mapping := range st.Mappings {
		if mapping.ID != id {
			return ErrInvalid
		}
	}
	if err := validate(&st); err != nil {
		return fmt.Errorf("cannot migrate persisted mappings: %w", err)
	}
	affected := affectedNodes(before, st)
	if len(affected) > 0 {
		st.Revision++
		for id := range affected {
			node := st.Nodes[id]
			node.DesiredRevision = st.Revision
			st.Nodes[id] = node
		}
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	var masterPrevious, masterBody []byte
	var hasMaster int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='master_config'").Scan(&hasMaster); err != nil {
		return err
	}
	if hasMaster != 0 {
		err := db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&masterPrevious)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			masterBody, _, err = config.UpgradeMasterDocument(masterPrevious)
			if err != nil {
				return fmt.Errorf("cannot migrate master configuration: %w", err)
			}
		}
	}
	backup, err := dbbackup.Create(db, path, key)
	if err != nil {
		return fmt.Errorf("pre-upgrade backup: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	update := func(query string, args ...any) error {
		result, err := tx.Exec(query, args...)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("database changed during migration; retry startup")
		}
		return nil
	}
	if err = update("UPDATE schema_version SET version=? WHERE version=5", schemaVersion); err != nil {
		return err
	}
	if err = update("UPDATE config SET data=? WHERE id=1 AND data=?", body, previous); err != nil {
		return err
	}
	if masterBody != nil {
		if err = update("UPDATE master_config SET data=? WHERE id=1 AND data=?", masterBody, masterPrevious); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	slog.Info("database upgraded", "from_schema", version, "to_schema", schemaVersion, "backup", backup)
	return nil
}
