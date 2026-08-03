package primitiveshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/nomed/yukh-coordination/internal/coordination"
	"github.com/nomed/yukh-coordination/internal/primitivesauth"
)

const MediaType = "application/yukh-coordination-primitives+json;version=1"

type Handler struct {
	bridge   *Bridge
	baseURI  string
	epoch    uint64
	deadline time.Duration
}

func NewHandler(bridge *Bridge, baseURI string, epoch uint64, deadline time.Duration) (*Handler, error) {
	parsed, err := url.Parse(baseURI)
	if bridge == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(baseURI, "/") || epoch == 0 || deadline <= 0 || deadline > 5*time.Second {
		return nil, primitivesauth.ErrInvalidArgument
	}
	return &Handler{bridge: bridge, baseURI: baseURI, epoch: epoch, deadline: deadline}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if request.TLS == nil || request.Method != http.MethodPost || request.URL.RawQuery != "" || request.URL.Fragment != "" || len(request.Cookies()) != 0 || request.Header.Get("Content-Encoding") != "" || request.Header.Get("Content-Type") != MediaType {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	authentication, err := requestAuthentication(request, handler.baseURI+request.URL.EscapedPath())
	if err != nil {
		writeProblem(writer, http.StatusUnauthorized, "unauthenticated")
		return
	}
	body, err := readCanonicalBody(request.Body)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.deadline)
	defer cancel()
	response, err := handler.dispatch(ctx, request.URL.Path, authentication, body)
	if err != nil {
		writeMappedProblem(writer, err)
		return
	}
	writeCanonical(writer, http.StatusOK, response)
}

func (handler *Handler) dispatch(ctx context.Context, path string, authentication primitivesauth.RequestAuthentication, body map[string]any) (map[string]any, error) {
	stringValue := func(name string) (string, bool) { value, ok := body[name].(string); return value, ok && value != "" }
	digest := func(name string) (coordination.Digest, bool) {
		value, ok := stringValue(name)
		return coordination.Digest(value), ok && validPublicDigest(value)
	}
	expiry := func() (time.Time, bool) {
		value, ok := stringValue("expires_at")
		if !ok {
			return time.Time{}, false
		}
		parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
		return parsed, err == nil
	}
	epoch, epochOK := body["epoch"].(float64)
	switch path {
	case "/coordination-primitives/v1/nonces:consume":
		if !exactKeys(body, "epoch", "expires_at", "scope_digest", "value_digest") || !epochOK || uint64(epoch) != handler.epoch || epoch != float64(uint64(epoch)) {
			return nil, primitivesauth.ErrInvalidArgument
		}
		scope, ok1 := digest("scope_digest")
		value, ok2 := digest("value_digest")
		expires, ok3 := expiry()
		if !ok1 || !ok2 || !ok3 {
			return nil, primitivesauth.ErrInvalidArgument
		}
		outcome, err := handler.bridge.Consume(ctx, authentication, scope, value, expires)
		return map[string]any{"outcome": string(outcome), "specversion": "1"}, err
	case "/coordination-primitives/v1/leases:acquire":
		if !exactKeys(body, "epoch", "expires_at", "holder_digest", "scope_digest") || !epochOK || uint64(epoch) != handler.epoch || epoch != float64(uint64(epoch)) {
			return nil, primitivesauth.ErrInvalidArgument
		}
		scope, ok1 := digest("scope_digest")
		holder, ok2 := digest("holder_digest")
		expires, ok3 := expiry()
		if !ok1 || !ok2 || !ok3 {
			return nil, primitivesauth.ErrInvalidArgument
		}
		result, err := handler.bridge.Acquire(ctx, authentication, scope, holder, expires)
		return leaseResponse("acquired", result.Capability, result.FencingToken, result.ExpiresAt), err
	case "/coordination-primitives/v1/leases:inspect":
		capability, ok := stringValue("lease_capability")
		if !ok || !exactKeys(body, "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		valid, err := handler.bridge.Inspect(ctx, authentication, capability)
		outcome := "stale"
		if valid {
			outcome = "valid"
		}
		return map[string]any{"outcome": outcome, "specversion": "1"}, err
	case "/coordination-primitives/v1/leases:renew":
		capability, ok1 := stringValue("lease_capability")
		expires, ok2 := expiry()
		if !ok1 || !ok2 || !exactKeys(body, "expires_at", "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		result, err := handler.bridge.Renew(ctx, authentication, capability, expires)
		return leaseResponse("renewed", result.Capability, result.FencingToken, result.ExpiresAt), err
	case "/coordination-primitives/v1/leases:release":
		capability, ok := stringValue("lease_capability")
		if !ok || !exactKeys(body, "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		err := handler.bridge.Release(ctx, authentication, capability)
		return map[string]any{"outcome": "released", "specversion": "1"}, err
	default:
		return nil, primitivesauth.ErrInvalidArgument
	}
}

func requestAuthentication(request *http.Request, target string) (primitivesauth.RequestAuthentication, error) {
	authorization := request.Header.Values("Authorization")
	proofs := request.Header.Values("DPoP")
	if len(authorization) != 1 || len(proofs) != 1 || !strings.HasPrefix(authorization[0], "DPoP ") {
		return primitivesauth.RequestAuthentication{}, primitivesauth.ErrUnauthenticated
	}
	return primitivesauth.NewRequestAuthentication(strings.TrimPrefix(authorization[0], "DPoP "), proofs[0], "POST", target)
}

func readCanonicalBody(reader io.Reader) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return nil, primitivesauth.ErrInvalidArgument
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, primitivesauth.ErrInvalidArgument
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	// Convert only the safe integer epoch explicitly; every other public member is a string.
	if number, ok := value["epoch"].(json.Number); ok {
		parsed, err := number.Int64()
		if err != nil || parsed <= 0 {
			return nil, primitivesauth.ErrInvalidArgument
		}
		value["epoch"] = float64(parsed)
	}
	return value, nil
}

func exactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}
func validPublicDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
func leaseResponse(outcome, capability string, fence uint64, expires time.Time) map[string]any {
	return map[string]any{"expires_at": expires.Format("2006-01-02T15:04:05.000Z"), "fencing_token": fence, "lease_capability": capability, "outcome": outcome, "specversion": "1"}
}

func writeMappedProblem(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, primitivesauth.ErrUnauthenticated):
		writeProblem(writer, 401, "unauthenticated")
	case errors.Is(err, primitivesauth.ErrAccessDenied):
		writeProblem(writer, 403, "access_denied")
	case errors.Is(err, primitivesauth.ErrInvalidCapability):
		writeProblem(writer, 409, "stale_fence")
	case errors.Is(err, primitivesauth.ErrInvalidArgument):
		writeProblem(writer, 400, "invalid_request")
	default:
		writeProblem(writer, 503, "temporarily_unavailable")
	}
}
func writeProblem(writer http.ResponseWriter, status int, code string) {
	writeCanonical(writer, status, map[string]any{"code": code, "status": status, "title": code, "type": "urn:yukh:coordination-primitives:problem:" + code})
}
func writeCanonical(writer http.ResponseWriter, status int, value map[string]any) {
	raw, _ := json.Marshal(value)
	canonical, _ := jsoncanonicalizer.Transform(raw)
	writer.Header().Set("Content-Type", MediaType)
	writer.WriteHeader(status)
	_, _ = writer.Write(canonical)
}
