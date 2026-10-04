package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"unicode"

	_ "modernc.org/sqlite"
)

// MasterConfigUpdate 设置页可更新的 master 配置字段
type MasterConfigUpdate struct {
	ListenAddr *string `json:"listen_addr"`
	Scheme     *string `json:"scheme"`
	CertFile   *string `json:"cert_file"`
	KeyFile    *string `json:"key_file"`
	WebMode    *string `json:"web_mode"`
}

// UpdateMasterConfig 更新 master_config 表中的通用配置（设置页运行时调用）
// 返回需要重启才能生效的字段列表
func UpdateMasterConfig(dbPath string, update MasterConfigUpdate) ([]string, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS master_config(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`); err != nil {
		return nil, err
	}
	var data []byte
	err = db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&data)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var needRestart []string
	set := func(key string, v any, restart bool) {
		raw, _ := json.Marshal(v)
		doc[key] = raw
		if restart {
			needRestart = append(needRestart, key)
		}
	}
	if update.ListenAddr != nil {
		set("ListenAddr", *update.ListenAddr, true)
	}
	if update.Scheme != nil {
		scheme := *update.Scheme
		if scheme != "http" && scheme != "https" {
			return nil, errors.New("scheme must be http or https")
		}
		set("Scheme", scheme, true)
	}
	if update.CertFile != nil {
		set("CertFile", *update.CertFile, true)
	}
	if update.KeyFile != nil {
		set("KeyFile", *update.KeyFile, true)
	}
	if update.WebMode != nil {
		mode := *update.WebMode
		if mode != "pull" && mode != "off" {
			return nil, errors.New("web_mode must be pull or off")
		}
		set("WebMode", mode, true)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec("UPDATE master_config SET data=? WHERE id=1", body)
	return needRestart, err
}

// MasterConfigView 设置页展示用的 master 配置（脱敏）
type MasterConfigView struct {
	ListenAddr string `json:"listen_addr"`
	Scheme     string `json:"scheme"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	WebMode    string `json:"web_mode"`
}

// GetMasterConfigView 从 DB 读取设置页展示用的配置
func GetMasterConfigView(dbPath string) (MasterConfigView, error) {
	var view MasterConfigView
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return view, err
	}
	defer db.Close()
	var data []byte
	err = db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&data)
	if err != nil {
		return view, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	// 不用 DisallowUnknownFields，兼容未来字段
	if err := decoder.Decode(&cfg); err != nil {
		return view, err
	}
	view.ListenAddr = cfg.ListenAddr
	view.Scheme = cfg.Scheme
	view.CertFile = cfg.CertFile
	view.KeyFile = cfg.KeyFile
	view.WebMode = cfg.WebMode
	if view.WebMode == "" {
		view.WebMode = "pull"
	}
	return view, nil
}

// UpdateWebConfig 更新 master_config 表中的前端拉取配置（设置页运行时调用）
func UpdateWebConfig(dbPath string, mirrors []string, version string, updateVersion bool, frontendURL *string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS master_config(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`); err != nil {
		return err
	}
	var data []byte
	err = db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&data)
	if err != nil {
		return err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	// mirrors 为 nil 时不覆盖（仅更新 frontendURL 的场景）
	if mirrors != nil {
		mirrorsRaw, _ := json.Marshal(mirrors)
		doc["WebMirrors"] = mirrorsRaw
	}
	// 兼容旧单值字段：清理
	delete(doc, "WebMirror")
	if updateVersion {
		versionRaw, _ := json.Marshal(version)
		doc["WebVersion"] = versionRaw
	}
	if frontendURL != nil {
		urlRaw, _ := json.Marshal(*frontendURL)
		doc["FrontendURL"] = urlRaw
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE master_config SET data=? WHERE id=1", body)
	return err
}

// PersistMaster resolves and immediately commits settings for non-listening callers.
// Master startup must use ResolveMaster and commit only after opening its listener.
func PersistMaster(local Config) (Config, error) {
	effective, commit, err := ResolveMaster(local)
	if err != nil {
		return local, err
	}
	if err := commit(); err != nil {
		return local, err
	}
	return effective, nil
}

// ResolveMaster resolves and validates defaults, stored settings and explicitly
// visited CLI flags in that order. Configs constructed without ParseFlags are
// fully explicit. Bootstrap paths and enroll tokens are excluded from storage.
// The returned commit rejects concurrent changes.
func ResolveMaster(local Config) (Config, func() error, error) {
	if local.Database == "" || local.DeploymentKey == "" {
		return local, nil, errors.New("database and deployment_key bootstrap paths required")
	}
	db, err := sql.Open("sqlite", local.Database)
	if err != nil {
		return local, nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS master_config(id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`); err != nil {
		return local, nil, err
	}
	effective := Defaults()
	var previous []byte
	err = db.QueryRow("SELECT data FROM master_config WHERE id=1").Scan(&previous)
	found := err == nil
	if found {
		decoder := json.NewDecoder(bytes.NewReader(previous))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&effective); err != nil {
			return local, nil, fmt.Errorf("invalid persisted master configuration: %w", err)
		}
		if err = decoder.Decode(new(any)); err != io.EOF {
			return local, nil, errors.New("invalid persisted master configuration")
		}
		overlayExplicit(reflect.ValueOf(&effective).Elem(), reflect.ValueOf(local), "", local.explicit)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return local, nil, err
	}
	if !found {
		overlayExplicit(reflect.ValueOf(&effective).Elem(), reflect.ValueOf(local), "", local.explicit)
	}
	effective.explicit = local.explicit
	effective.Database = local.Database
	effective.DeploymentKey = local.DeploymentKey
	effective.EnrollToken = local.EnrollToken
	if effective.Scheme == "" && !effective.explicit["scheme"] {
		effective.Scheme = "http"
	}
	if err = effective.Validate("master"); err != nil {
		return local, nil, fmt.Errorf("master configuration: %w", err)
	}
	if effective.Scheme == "https" {
		pair, err := tls.LoadX509KeyPair(effective.CertFile, effective.KeyFile)
		if err != nil {
			return local, nil, fmt.Errorf("master control TLS: %w", err)
		}
		if effective.EmbeddedServer.Enabled {
			ca := effective.ControlCA
			if ca == "" {
				ca = effective.CertFile
			}
			pem, err := os.ReadFile(ca)
			if err != nil {
				return local, nil, fmt.Errorf("embedded control CA: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return local, nil, errors.New("embedded control CA: invalid certificate PEM")
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return local, nil, fmt.Errorf("master control certificate: %w", err)
			}
			intermediates := x509.NewCertPool()
			for _, der := range pair.Certificate[1:] {
				certificate, err := x509.ParseCertificate(der)
				if err != nil {
					return local, nil, fmt.Errorf("master control certificate chain: %w", err)
				}
				intermediates.AddCert(certificate)
			}
			name := effective.ControlServerName
			if name == "" {
				name, _, _ = net.SplitHostPort(effective.ListenAddr)
				switch name {
				case "", "0.0.0.0":
					name = "127.0.0.1"
				case "::":
					name = "::1"
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return local, nil, fmt.Errorf("embedded control TLS trust: %w", err)
			}
		}
	}
	body, err := json.Marshal(effective)
	if err != nil {
		return local, nil, err
	}
	var document map[string]json.RawMessage
	if err = json.Unmarshal(body, &document); err != nil {
		return local, nil, err
	}
	delete(document, "Database")
	delete(document, "DeploymentKey")
	delete(document, "EnrollToken")
	body, err = json.Marshal(document)
	if err != nil {
		return local, nil, err
	}
	commit := func() error {
		db, err := sql.Open("sqlite", local.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		db.SetMaxOpenConns(1)
		if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
			return err
		}
		var result sql.Result
		if found {
			result, err = db.Exec("UPDATE master_config SET data=? WHERE id=1 AND data=?", body, previous)
		} else {
			result, err = db.Exec("INSERT INTO master_config(id,data) VALUES(1,?) ON CONFLICT(id) DO NOTHING", body)
		}
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed != 1 {
			return errors.New("master configuration changed during startup; retry startup")
		}
		return nil
	}
	return effective, commit, nil
}

func overlayExplicit(dst, src reflect.Value, prefix string, fields map[string]bool) {
	for i := 0; i < dst.NumField(); i++ {
		field := dst.Field(i)
		if !field.CanSet() {
			continue
		}
		name := prefix + snakeCase(dst.Type().Field(i).Name)
		if fields == nil || fields[name] {
			field.Set(src.Field(i))
		} else if field.Kind() == reflect.Struct {
			overlayExplicit(field, src.Field(i), name+".", fields)
		}
	}
}

func snakeCase(s string) string {
	switch s {
	case "HTMLDir":
		return "html_dir"
	case "NodeID":
		return "node_id"
	case "ControlCA":
		return "control_ca"
	}
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
