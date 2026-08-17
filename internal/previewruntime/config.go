package previewruntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
)

const ConfigProfile = "yukh-coordination/local-preview-runtime-v1"

var ErrInvalidConfiguration = errors.New("preview runtime: invalid configuration")

type configDocument struct {
	Profile           string `json:"profile"`
	PublicBaseURI     string `json:"public_base_uri"`
	PublicBind        string `json:"public_bind"`
	SupervisorBind    string `json:"supervisor_bind"`
	NATSURL           string `json:"nats_url"`
	TLSCertificate    string `json:"tls_certificate"`
	TLSPrivateKey     string `json:"tls_private_key"`
	SupervisorToken   string `json:"supervisor_token"`
	ReceiptSigningKey string `json:"receipt_signing_key"`
}

type Config struct{ value configDocument }

func LoadConfig(path string) (*Config, error) {
	if !exactPath(path) {
		return nil, relayInvalid()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 2 || info.Size() > 16<<10 {
		return nil, relayInvalid()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, relayInvalid()
	}
	var value configDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validConfig(value) {
		return nil, relayInvalid()
	}
	return &Config{value: value}, nil
}

func validConfig(value configDocument) bool {
	if value.Profile != ConfigProfile || !httpsBase(value.PublicBaseURI) || !bind(value.PublicBind) || !bind(value.SupervisorBind) || value.PublicBind == value.SupervisorBind || !localNATSURL(value.NATSURL) {
		return false
	}
	paths := []string{
		value.TLSCertificate,
		value.TLSPrivateKey,
		value.SupervisorToken,
		value.ReceiptSigningKey,
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !exactPath(path) || seen[path] {
			return false
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 64<<10 {
			return false
		}
	}
	token, err := os.ReadFile(value.SupervisorToken)
	if err != nil || len(token) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(token))
	validToken := err == nil && len(decoded) == 32 && !zero(decoded)
	clear(decoded)
	clear(token)
	if !validToken {
		return false
	}
	receiptSeed, err := os.ReadFile(value.ReceiptSigningKey)
	validReceiptKey := err == nil && len(receiptSeed) == ed25519.SeedSize && !zero(receiptSeed)
	clear(receiptSeed)
	if !validReceiptKey {
		return false
	}
	return true
}

func bind(value string) bool {
	host, port, err := net.SplitHostPort(value)
	return err == nil && port != "" && (host == "0.0.0.0" || host == "127.0.0.1")
}

func exactPath(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

func (c *Config) PublicBaseURI() string   { return c.value.PublicBaseURI }
func (c *Config) PublicBind() string      { return c.value.PublicBind }
func (c *Config) SupervisorBind() string  { return c.value.SupervisorBind }
func (c *Config) NATSURL() string         { return c.value.NATSURL }
func (c *Config) TLSCertificate() string  { return c.value.TLSCertificate }
func (c *Config) TLSPrivateKey() string   { return c.value.TLSPrivateKey }
func (c *Config) SupervisorToken() string { return c.value.SupervisorToken }
func (c *Config) ReceiptSigningKey() string {
	return c.value.ReceiptSigningKey
}

func relayInvalid() error { return ErrInvalidConfiguration }
