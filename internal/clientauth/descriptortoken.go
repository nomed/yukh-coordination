package clientauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type DescriptorTokenSource struct {
	mu         sync.Mutex
	descriptor int
}

func NewDescriptorTokenSource(descriptor int) (*DescriptorTokenSource, error) {
	if descriptor < 3 {
		return nil, ErrInvalidCredential
	}
	return &DescriptorTokenSource{descriptor: descriptor}, nil
}

// Acquire performs one bounded exchange over an inherited connected local
// socket. It sends only the public DPoP key and accepts one token response bound
// to that key. The socket is consumed and closed; no endpoint is discovered.
func (s *DescriptorTokenSource) Acquire(ctx context.Context, public PublicP256JWK) (*BoundAccessToken, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrExternalToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.descriptor < 3 {
		return nil, ErrExternalToken
	}
	descriptor := s.descriptor
	s.descriptor = -1
	file := os.NewFile(uintptr(descriptor), "external-token-supervisor")
	if file == nil {
		return nil, ErrExternalToken
	}
	info, err := file.Stat()
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		file.Close()
		return nil, ErrExternalToken
	}
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, ErrExternalToken
	}
	defer connection.Close()
	if _, local := connection.(*net.UnixConn); !local {
		return nil, ErrExternalToken
	}
	deadline := time.Now().Add(10 * time.Second)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if connection.SetDeadline(deadline) != nil {
		return nil, ErrExternalToken
	}
	x, y := public.Coordinates()
	thumbprint := public.Thumbprint()
	request, err := json.Marshal(map[string]any{
		"crv": "P-256", "dpop_thumbprint": base64.RawURLEncoding.EncodeToString(thumbprint[:]),
		"kty": "EC", "schema": 1, "x": base64.RawURLEncoding.EncodeToString(x[:]), "y": base64.RawURLEncoding.EncodeToString(y[:]),
	})
	if err != nil {
		return nil, ErrExternalToken
	}
	request, err = jsoncanonicalizer.Transform(request)
	if err != nil || len(request) > 1024 {
		return nil, ErrExternalToken
	}
	request = append(request, '\n')
	if _, err := connection.Write(request); err != nil {
		clear(request)
		return nil, ErrExternalToken
	}
	clear(request)
	raw, err := io.ReadAll(io.LimitReader(connection, maxAccessTokenBytes+1))
	if err != nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > maxAccessTokenBytes {
		clear(raw)
		return nil, ErrExternalToken
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(raw)
		clear(canonical)
		return nil, ErrExternalToken
	}
	clear(canonical)
	var document struct {
		Credential     string `json:"credential"`
		DPoPThumbprint string `json:"dpop_thumbprint"`
		ExpiresAt      string `json:"expires_at"`
		Schema         int    `json:"schema"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != 1 {
		clear(raw)
		return nil, ErrExternalToken
	}
	responseThumbprint, err := base64.RawURLEncoding.Strict().DecodeString(document.DPoPThumbprint)
	expiresAt, timeErr := time.Parse("2006-01-02T15:04:05.000Z", document.ExpiresAt)
	if err != nil || timeErr != nil || expiresAt.Location() != time.UTC || len(responseThumbprint) != len(thumbprint) || subtle.ConstantTimeCompare(responseThumbprint, thumbprint[:]) != 1 {
		clear(responseThumbprint)
		clear(raw)
		return nil, ErrExternalToken
	}
	token, err := NewBoundAccessToken(document.Credential, expiresAt)
	document.Credential = ""
	clear(responseThumbprint)
	clear(raw)
	if err != nil {
		return nil, ErrExternalToken
	}
	return token, nil
}
