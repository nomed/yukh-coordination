package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const maxJWKSBytes = 256 * 1024

type JWKSConfig struct {
	URL            string
	Roots          *x509.CertPool
	Algorithms     []jose.SignatureAlgorithm
	SoftRefresh    time.Duration
	HardMaxAge     time.Duration
	RequestTimeout time.Duration
}

type jwksCache struct {
	mu                 sync.Mutex
	url                string
	client             *http.Client
	algorithms         map[jose.SignatureAlgorithm]struct{}
	softRefresh        time.Duration
	hardMaxAge         time.Duration
	now                func() time.Time
	keys               map[string]jose.JSONWebKey
	fetchedAt          time.Time
	lastUnknownRefresh time.Time
}

func newJWKSCache(ctx context.Context, config JWKSConfig, now func() time.Time) (*jwksCache, error) {
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != config.URL || config.Roots == nil || config.SoftRefresh <= 0 || config.HardMaxAge <= config.SoftRefresh || config.HardMaxAge > 5*time.Minute || config.RequestTimeout <= 0 || config.RequestTimeout > 30*time.Second || now == nil {
		return nil, errUnavailable
	}
	algorithms := make(map[jose.SignatureAlgorithm]struct{}, len(config.Algorithms))
	for _, algorithm := range config.Algorithms {
		if !allowedJWTAlgorithm(algorithm) {
			return nil, errUnavailable
		}
		algorithms[algorithm] = struct{}{}
	}
	if _, ok := algorithms[jose.RS256]; !ok {
		return nil, errUnavailable
	}
	dialer := &net.Dialer{Timeout: config.RequestTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.Roots},
		TLSHandshakeTimeout: config.RequestTimeout, ResponseHeaderTimeout: config.RequestTimeout,
		DisableCompression: true,
	}
	cache := &jwksCache{
		url: config.URL, algorithms: algorithms, softRefresh: config.SoftRefresh, hardMaxAge: config.HardMaxAge, now: now,
		client: &http.Client{Transport: transport, Timeout: config.RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errUnavailable }},
	}
	keys, err := cache.fetch(ctx)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, errUnavailable
	}
	cache.keys = keys
	cache.fetchedAt = now().UTC()
	return cache, nil
}

func (c *jwksCache) close() {
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *jwksCache) key(ctx context.Context, kid string, algorithm jose.SignatureAlgorithm) (jose.JSONWebKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	age := now.Sub(c.fetchedAt)
	if age < 0 {
		return jose.JSONWebKey{}, errUnavailable
	}
	refreshAttempted := false
	refreshFailed := false
	if age >= c.softRefresh {
		refreshAttempted = true
		if keys, err := c.fetch(ctx); err == nil {
			c.keys = keys
			c.fetchedAt = now
			age = 0
		} else {
			refreshFailed = true
			if age >= c.hardMaxAge {
				return jose.JSONWebKey{}, errUnavailable
			}
		}
	}
	if key, ok := c.keys[kid]; ok {
		if !keyMatchesAlgorithm(key, algorithm) {
			return jose.JSONWebKey{}, errInvalid
		}
		return key, nil
	}
	if refreshAttempted {
		c.lastUnknownRefresh = now
		if refreshFailed {
			return jose.JSONWebKey{}, errUnavailable
		}
		return jose.JSONWebKey{}, errInvalid
	}
	if !c.lastUnknownRefresh.IsZero() && now.Sub(c.lastUnknownRefresh) < 30*time.Second {
		return jose.JSONWebKey{}, errInvalid
	}
	c.lastUnknownRefresh = now
	keys, err := c.fetch(ctx)
	if err != nil {
		return jose.JSONWebKey{}, errUnavailable
	}
	c.keys = keys
	c.fetchedAt = now
	key, ok := c.keys[kid]
	if !ok || !keyMatchesAlgorithm(key, algorithm) {
		return jose.JSONWebKey{}, errInvalid
	}
	return key, nil
}

func (c *jwksCache) fetch(ctx context.Context) (map[string]jose.JSONWebKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, errUnavailable
	}
	request.Header.Set("Accept", "application/jwk-set+json, application/json")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, errUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Uncompressed || response.ContentLength > maxJWKSBytes {
		return nil, errUnavailable
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/json" && mediaType != "application/jwk-set+json") {
		return nil, errUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return nil, errUnavailable
	}
	return parseJWKS(body, c.algorithms)
}

func parseJWKS(data []byte, algorithms map[jose.SignatureAlgorithm]struct{}) (map[string]jose.JSONWebKey, error) {
	if err := scanJSONObject(data, maxJWKSBytes); err != nil {
		return nil, errUnavailable
	}
	root, err := rawObject(data, "keys")
	if err != nil {
		return nil, errUnavailable
	}
	var rawKeys []json.RawMessage
	if err := json.Unmarshal(root["keys"], &rawKeys); err != nil || len(rawKeys) == 0 || len(rawKeys) > 32 {
		return nil, errUnavailable
	}
	result := make(map[string]jose.JSONWebKey, len(rawKeys))
	for _, raw := range rawKeys {
		if err := scanJSONObject(raw, 16*1024); err != nil || hasForbiddenJWKMember(raw) {
			return nil, errUnavailable
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil || !key.Valid() || !key.IsPublic() || key.KeyID == "" || len(key.KeyID) > 128 || !asciiIdentifier(key.KeyID) || key.CertificatesURL != nil {
			return nil, errUnavailable
		}
		if _, exists := result[key.KeyID]; exists || !validJWKSKey(key, algorithms) || !validKeyOps(raw) {
			return nil, errUnavailable
		}
		result[key.KeyID] = key
	}
	return result, nil
}

func hasForbiddenJWKMember(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return true
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5u", "jku"} {
		if _, exists := object[name]; exists {
			return true
		}
	}
	return false
}

func validKeyOps(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	value, exists := object["key_ops"]
	if !exists {
		return true
	}
	var operations []string
	return json.Unmarshal(value, &operations) == nil && len(operations) == 1 && operations[0] == "verify"
}

func validJWKSKey(key jose.JSONWebKey, algorithms map[jose.SignatureAlgorithm]struct{}) bool {
	if key.Use != "" && key.Use != "sig" {
		return false
	}
	if key.Algorithm != "" {
		if _, ok := algorithms[jose.SignatureAlgorithm(key.Algorithm)]; !ok {
			return false
		}
		return keyMatchesAlgorithm(key, jose.SignatureAlgorithm(key.Algorithm))
	}
	for algorithm := range algorithms {
		if keyMatchesAlgorithm(key, algorithm) {
			return true
		}
	}
	return false
}

func keyMatchesAlgorithm(key jose.JSONWebKey, algorithm jose.SignatureAlgorithm) bool {
	if key.Algorithm != "" && key.Algorithm != string(algorithm) {
		return false
	}
	switch public := key.Key.(type) {
	case *rsa.PublicKey:
		return (algorithm == jose.RS256 || algorithm == jose.PS256) && public.N.BitLen() >= 2048 && public.E >= 3 && public.E%2 == 1
	case *ecdsa.PublicKey:
		return algorithm == jose.ES256 && public.Curve == elliptic.P256() && public.Curve.IsOnCurve(public.X, public.Y)
	case ed25519.PublicKey:
		return algorithm == jose.EdDSA && len(public) == ed25519.PublicKeySize
	default:
		return false
	}
}

func allowedJWTAlgorithm(algorithm jose.SignatureAlgorithm) bool {
	return algorithm == jose.RS256 || algorithm == jose.PS256 || algorithm == jose.ES256 || algorithm == jose.EdDSA
}

func asciiIdentifier(value string) bool {
	if !asciiOnly(value) {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune(`"\\`, character) {
			return false
		}
	}
	return true
}
