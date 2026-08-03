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

const maxMessageBytes = 4096

type Handler struct {
	bridge   *Bridge
	baseURI  string
	epoch    uint64
	deadline time.Duration
	slots    chan struct{}
}

func NewHandler(bridge *Bridge, baseURI string, epoch uint64, deadline time.Duration, maxConcurrent int) (*Handler, error) {
	parsed, err := url.Parse(baseURI)
	if bridge == nil || err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.HasSuffix(baseURI, "/") || epoch == 0 || deadline <= 0 || deadline > 5*time.Second || maxConcurrent < 1 {
		return nil, primitivesauth.ErrInvalidArgument
	}
	return &Handler{bridge: bridge, baseURI: baseURI, epoch: epoch, deadline: deadline, slots: make(chan struct{}, maxConcurrent)}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	action, knownRoute := actionForPath(request.URL.Path)
	if request.TLS == nil || request.Method != http.MethodPost || !knownRoute || request.URL.RawQuery != "" || request.URL.Fragment != "" || len(request.Cookies()) != 0 || request.Header.Get("Content-Encoding") != "" || request.Header.Get("Content-Type") != MediaType {
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		writeProblem(writer, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.deadline)
	defer cancel()
	authentication, err := requestAuthentication(request, handler.baseURI+request.URL.EscapedPath())
	if err != nil {
		writeProblem(writer, http.StatusUnauthorized, "unauthenticated")
		return
	}
	identity, err := handler.bridge.Admit(ctx, authentication, action)
	if err != nil {
		writeMappedProblem(writer, err)
		return
	}
	body, err := readCanonicalBody(ctx, request.Body)
	if err != nil {
		if errors.Is(err, primitivesauth.ErrTemporarilyUnavailable) {
			writeMappedProblem(writer, err)
			return
		}
		writeProblem(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	response, err := handler.dispatch(ctx, request.URL.Path, identity, body)
	if err != nil {
		writeMappedProblem(writer, err)
		return
	}
	if !writeCanonical(writer, http.StatusOK, response) {
		writeProblem(writer, http.StatusInternalServerError, "invariant_violation")
	}
}

func (handler *Handler) dispatch(ctx context.Context, path string, identity primitivesauth.Identity, body map[string]any) (map[string]any, error) {
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
		outcome, err := handler.bridge.ConsumeAdmitted(ctx, identity, scope, value, expires)
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
		result, err := handler.bridge.AcquireAdmitted(ctx, identity, scope, holder, expires)
		return leaseResponse("acquired", result.Capability, result.FencingToken, result.ExpiresAt), err
	case "/coordination-primitives/v1/leases:inspect":
		capability, ok := stringValue("lease_capability")
		if !ok || !exactKeys(body, "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		status, err := handler.bridge.InspectAdmitted(ctx, identity, capability)
		return map[string]any{"outcome": string(status), "specversion": "1"}, err
	case "/coordination-primitives/v1/leases:renew":
		capability, ok1 := stringValue("lease_capability")
		expires, ok2 := expiry()
		if !ok1 || !ok2 || !exactKeys(body, "expires_at", "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		result, err := handler.bridge.RenewAdmitted(ctx, identity, capability, expires)
		return leaseResponse("renewed", result.Capability, result.FencingToken, result.ExpiresAt), err
	case "/coordination-primitives/v1/leases:release":
		capability, ok := stringValue("lease_capability")
		if !ok || !exactKeys(body, "lease_capability") {
			return nil, primitivesauth.ErrInvalidArgument
		}
		err := handler.bridge.ReleaseAdmitted(ctx, identity, capability)
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

func readCanonicalBody(ctx context.Context, body io.ReadCloser) (map[string]any, error) {
	type result struct {
		raw []byte
		err error
	}
	completed := make(chan result, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(body, maxMessageBytes+1))
		completed <- result{raw: raw, err: err}
	}()
	var raw []byte
	select {
	case <-ctx.Done():
		_ = body.Close()
		<-completed
		return nil, primitivesauth.ErrTemporarilyUnavailable
	case observed := <-completed:
		if ctx.Err() != nil {
			return nil, primitivesauth.ErrTemporarilyUnavailable
		}
		raw = observed.raw
		if observed.err != nil {
			return nil, primitivesauth.ErrInvalidArgument
		}
	}
	if len(raw) == 0 || len(raw) > maxMessageBytes {
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
	case errors.Is(err, primitivesauth.ErrInvariantViolation):
		writeProblem(writer, 500, "invariant_violation")
	case errors.Is(err, primitivesauth.ErrConflict):
		writeProblem(writer, 409, "conflict")
	default:
		writeProblem(writer, 503, "temporarily_unavailable")
	}
}
func writeProblem(writer http.ResponseWriter, status int, code string) {
	_ = writeCanonical(writer, status, map[string]any{"code": code, "status": status, "title": code, "type": "urn:yukh:coordination-primitives:problem:" + code})
}
func writeCanonical(writer http.ResponseWriter, status int, value map[string]any) bool {
	raw, _ := json.Marshal(value)
	canonical, _ := jsoncanonicalizer.Transform(raw)
	if len(canonical) == 0 || len(canonical) > maxMessageBytes {
		return false
	}
	writer.Header().Set("Content-Type", MediaType)
	writer.WriteHeader(status)
	_, _ = writer.Write(canonical)
	return true
}

func actionForPath(path string) (primitivesauth.Action, bool) {
	switch path {
	case "/coordination-primitives/v1/nonces:consume":
		return primitivesauth.NonceConsume, true
	case "/coordination-primitives/v1/leases:acquire":
		return primitivesauth.LeaseAcquire, true
	case "/coordination-primitives/v1/leases:inspect":
		return primitivesauth.LeaseInspect, true
	case "/coordination-primitives/v1/leases:renew":
		return primitivesauth.LeaseRenew, true
	case "/coordination-primitives/v1/leases:release":
		return primitivesauth.LeaseRelease, true
	default:
		return "", false
	}
}
