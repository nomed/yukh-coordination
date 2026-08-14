package previewruntime

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/clientauth"
)

type Supervisor struct {
	authority  *Authority
	token      [sha256.Size]byte
	receiptKey string
}

func NewSupervisor(authority *Authority, token, receiptKey string) (*Supervisor, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	receipt, receiptErr := base64.RawURLEncoding.Strict().DecodeString(receiptKey)
	if authority == nil || err != nil || len(decoded) != sha256.Size || zero(decoded) || receiptErr != nil || len(receipt) != 32 {
		clear(decoded)
		clear(receipt)
		return nil, relayInvalid()
	}
	var value [sha256.Size]byte
	copy(value[:], decoded)
	clear(decoded)
	clear(receipt)
	return &Supervisor{authority: authority, token: value, receiptKey: receiptKey}, nil
}

func (s *Supervisor) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.TLS == nil || request.URL.RawQuery != "" {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	provided := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(provided)
	if err != nil || len(decoded) != len(s.token) || subtle.ConstantTimeCompare(decoded, s.token[:]) != 1 {
		clear(decoded)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	clear(decoded)
	if request.Method == http.MethodGet && request.URL.Path == "/local-preview/v1/config" {
		response, _ := json.Marshal(map[string]any{"channel_id": PreviewChannelID, "channel_uri": PreviewChannelURI, "receipt_key": s.receiptKey, "receipt_key_id": "local-preview-receipt-1", "schema": 1, "transcript_epoch": 1})
		response, _ = jsoncanonicalizer.Transform(response)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(response)
		return
	}
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	slot := strings.TrimPrefix(request.URL.Path, "/local-preview/v1/external-token/")
	if slot != "agent-a" && slot != "agent-b" {
		http.NotFound(writer, request)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1025))
	if err != nil || len(raw) == 0 || len(raw) > 1024 {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	var document struct {
		Curve      string `json:"crv"`
		Thumbprint string `json:"dpop_thumbprint"`
		KeyType    string `json:"kty"`
		Schema     int    `json:"schema"`
		X          string `json:"x"`
		Y          string `json:"y"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || document.Schema != 1 || document.Curve != "P-256" || document.KeyType != "EC" {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	x, xErr := base64.RawURLEncoding.Strict().DecodeString(document.X)
	y, yErr := base64.RawURLEncoding.Strict().DecodeString(document.Y)
	jwk, jwkErr := clientauth.NewPublicP256JWK(x, y)
	clear(x)
	clear(y)
	thumbprint := jwk.Thumbprint()
	providedThumbprint, thumbErr := base64.RawURLEncoding.Strict().DecodeString(document.Thumbprint)
	if xErr != nil || yErr != nil || jwkErr != nil || thumbErr != nil || len(providedThumbprint) != len(thumbprint) || subtle.ConstantTimeCompare(providedThumbprint, thumbprint[:]) != 1 {
		clear(providedThumbprint)
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	clear(providedThumbprint)
	issued, err := s.authority.Issue(slot, thumbprint)
	if err != nil {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return
	}
	response, _ := json.Marshal(map[string]any{"credential": issued.Credential, "dpop_thumbprint": document.Thumbprint, "expires_at": issued.ExpiresAt.Format("2006-01-02T15:04:05.000Z"), "schema": 1})
	response, _ = jsoncanonicalizer.Transform(response)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)
	_, _ = writer.Write(response)
}
