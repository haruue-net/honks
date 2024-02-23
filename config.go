package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/flynn/json5"
	"strconv"
)

type Config struct {
	Listen     ListenConfig `json:"listen"`
	Timeout    int          `json:"timeout"`
	DisableUDP bool         `json:"disable_udp"`
	Users      UsersConfig  `json:"users"`
	LogLevel   LogLevel     `json:"log_level"`
}

type ListenConfig []string

func (c *ListenConfig) MarshalJSON() ([]byte, error) {
	switch len(*c) {
	case 0:
		return json.Marshal(nil)
	case 1:
		return json.Marshal((*c)[0])
	default:
		return json.Marshal([]string(*c))
	}
}

func (c *ListenConfig) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*c = nil
		return nil
	}
	if len(b) < 1 {
		return fmt.Errorf("unable to unmarshal ListenConfig from %s", strconv.Quote(string(b)))
	}
	switch b[0] {
	case '"':
		var s string
		if err := json5.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("unable to unmarshal ListenConfig from %s: %w", strconv.Quote(string(b)), err)
		}
		*c = ListenConfig{s}
	case '[':
		var a []string
		if err := json5.Unmarshal(b, &a); err != nil {
			return fmt.Errorf("unable to unmarshal ListenConfig from %s: %w", strconv.Quote(string(b)), err)
		}
		*c = a
	default:
		return fmt.Errorf("unable to unmarshal ListenConfig from %s", strconv.Quote(string(b)))
	}
	return nil
}

type UsersConfig map[string]string

type DeprecatedUserEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (c *UsersConfig) MarshalJSON() ([]byte, error) {
	if *c == nil || len(*c) == 0 {
		return json.Marshal(nil)
	}
	return json.Marshal(map[string]string(*c))
}

func (c *UsersConfig) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*c = nil
		return nil
	}
	if len(b) < 1 {
		return fmt.Errorf("unable to unmarshal UsersConfig from %s", strconv.Quote(string(b)))
	}
	var m map[string]string
	switch b[0] {
	case '{':
		if err := json5.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("unable to unmarshal UsersConfig from %s: %w", strconv.Quote(string(b)), err)
		}
	case '[':
		var a []DeprecatedUserEntry
		if err := json5.Unmarshal(b, &a); err != nil {
			return fmt.Errorf("unable to unmarshal UsersConfig from %s: %w", strconv.Quote(string(b)), err)
		}
		m = make(map[string]string, len(a))
		for _, u := range a {
			m[u.Username] = u.Password
		}
	default:
		return fmt.Errorf("unable to unmarshal UsersConfig from %s", strconv.Quote(string(b)))
	}
	*c = m
	return nil
}

func (c *UsersConfig) AuthEnabled() bool {
	return *c != nil && len(*c) > 0
}

func (c *UsersConfig) AuthFunc(username, password string) bool {
	if pass, ok := (*c)[username]; ok {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1 {
			logVerbose("user %s authenticated\n", username)
			return true
		}
		logError("user %s authentication failed\n", username)
		return false
	}
	logError("user %s not found\n", username)
	return false
}
