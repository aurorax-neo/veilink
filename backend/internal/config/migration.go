package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// UpgradeMasterDocument removes only known retired Web settings. All other
// fields still go through the same strict decoder used at startup.
func UpgradeMasterDocument(raw []byte) ([]byte, bool, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, err
	}
	if doc == nil {
		return nil, false, errors.New("master configuration must be an object")
	}
	changed := false
	for key := range doc {
		switch strings.ToLower(strings.ReplaceAll(key, "_", "")) {
		case "webmode", "webversion", "webmirror", "webmirrors", "frontendurl", "htmldir":
			delete(doc, key)
			changed = true
		}
	}
	body := raw
	if changed {
		var err error
		body, err = json.Marshal(doc)
		if err != nil {
			return nil, false, err
		}
	}
	var c Config
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, false, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, false, io.ErrUnexpectedEOF
	}
	return body, changed, nil
}
