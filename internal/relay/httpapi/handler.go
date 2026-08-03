// Package httpapi implements the accepted HTTP/SSE binding from RFC-0004.
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/nomed/yukh-coordination/internal/relay"
)

const (
	EventMediaType          = "application/yukh-event+json"
	ReceiptMediaType        = "application/yukh-receipt+json;version=0.1"
	SessionMediaType        = "application/yukh-session+json;version=0.1"
	TranscriptBaseMediaType = "application/yukh-transcript+json"
	TranscriptMediaType     = "application/yukh-transcript+json;version=0.1"
	ProblemMediaType        = "application/problem+json"
	maxEventBytes           = 65_536
	maxRequestTarget        = 4_096
	maxHeaders              = 64
	maxAuthorizationBytes   = 8_192
	maxDPoPProofBytes       = 16_384
	maxSafeInteger          = 9_007_199_254_740_991
)

type Action string

const (
	ActionPublish Action = "publish"
	ActionReplay  Action = "replay"
	ActionWatch   Action = "watch"
)

type Identity struct {
	TenantID              string
	PrincipalID           string
	ParticipantInstanceID string
	SessionEpoch          uint64
}

type AccessRequest struct {
	Identity Identity
	Channel  relay.ChannelKey
	Action   Action
}

type Decision struct {
	Allowed           bool
	CanonicalBinding  []byte
	ACLPolicyVersion  string
	ACLPolicyDigest   string
	DecisionReceiptID string
	Revoked           <-chan struct{}
}

type Authorizer interface {
	Authorize(context.Context, AccessRequest) (Decision, error)
}

type AdmittedRequest struct {
	Identity             Identity
	Channel              relay.ChannelKey
	AuthorizationBinding []byte
	ACLPolicyVersion     string
	ACLPolicyDigest      string
	ACLDecisionReceiptID string
}

type AppendResponse struct {
	Outcome          relay.AppendOutcome
	CanonicalReceipt []byte
}

type ReplayRequest struct {
	AdmittedRequest
	After uint64
	Limit int
}

type StreamRecord struct {
	Sequence        uint64
	CanonicalRecord []byte
}

type StreamItem struct {
	Record             *StreamRecord
	IncompleteBoundary *uint64
	Err                error
}

type Application interface {
	Append(context.Context, AdmittedRequest, []byte) (AppendResponse, error)
	Replay(context.Context, ReplayRequest) ([]byte, error)
	Stream(context.Context, ReplayRequest) (<-chan StreamItem, error)
}

type Config struct {
	PublicBaseURI     string
	HeartbeatInterval time.Duration
	MaxStreamLifetime time.Duration
	WriteTimeout      time.Duration
}

type Handler struct {
	bootstrapper  SessionBootstrapper
	authenticator Authenticator
	authorizer    Authorizer
	application   Application
	config        Config
	publicBase    *url.URL
}

func New(bootstrapper SessionBootstrapper, authenticator Authenticator, authorizer Authorizer, application Application, config Config) (*Handler, error) {
	if bootstrapper == nil || authenticator == nil || authorizer == nil || application == nil {
		return nil, relay.ErrInvalidArgument
	}
	publicBase, err := parsePublicBaseURI(config.PublicBaseURI)
	if err != nil {
		return nil, relay.ErrInvalidArgument
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = 15 * time.Second
	}
	if config.MaxStreamLifetime <= 0 || config.MaxStreamLifetime > 15*time.Minute {
		config.MaxStreamLifetime = 15 * time.Minute
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	return &Handler{bootstrapper: bootstrapper, authenticator: authenticator, authorizer: authorizer, application: application, config: config, publicBase: publicBase}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Yukh-Request-ID", requestID)

	route, err := parseRoute(r)
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if err := checkFraming(r); err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if route.bootstrap {
		if err := checkBootstrapFraming(r); err != nil {
			writeProblem(w, requestID, http.StatusBadRequest, "invalid_request", "Invalid request")
			return
		}
	} else if encoding := r.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		writeProblem(w, requestID, http.StatusUnsupportedMediaType, "unsupported_content_encoding", "Unsupported content encoding")
		return
	}
	if route.action == ActionPublish && r.ContentLength > maxEventBytes {
		writeProblem(w, requestID, http.StatusRequestEntityTooLarge, "event_too_large", "Event too large")
		return
	}
	if r.TLS == nil {
		writeProblem(w, requestID, http.StatusBadRequest, "tls_required", "TLS required")
		return
	}
	targetURI, err := h.publicTarget(r.URL.EscapedPath())
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	credential, proof, err := dpopAuthentication(r.Header.Values("Authorization"), r.Header.Values("DPoP"))
	if err != nil {
		setDPoPChallenge(w)
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated", "Authentication required")
		return
	}
	if route.bootstrap {
		h.bootstrap(w, r, requestID, newBootstrapAuthentication(credential, proof, r.Method, targetURI))
		return
	}
	identity, err := h.authenticator.Authenticate(r.Context(), newSessionAuthentication(credential, proof, r.Method, targetURI))
	if err != nil || !validIdentity(identity) {
		writeAuthenticationProblem(w, requestID, err)
		return
	}
	route.channel.TenantID = identity.TenantID
	decision, err := h.authorizer.Authorize(r.Context(), AccessRequest{Identity: identity, Channel: route.channel, Action: route.action})
	if err != nil || !validDecision(decision) {
		writeProblem(w, requestID, http.StatusNotFound, "resource_unavailable", "Resource unavailable")
		return
	}
	admitted := AdmittedRequest{
		Identity: identity, Channel: route.channel,
		AuthorizationBinding: bytes.Clone(decision.CanonicalBinding),
		ACLPolicyVersion:     decision.ACLPolicyVersion, ACLPolicyDigest: decision.ACLPolicyDigest,
		ACLDecisionReceiptID: decision.DecisionReceiptID,
	}

	switch route.action {
	case ActionPublish:
		h.append(w, r, requestID, admitted)
	case ActionReplay:
		h.replay(w, r, requestID, admitted, route.after, route.limit)
	case ActionWatch:
		h.stream(w, r, requestID, admitted, route.after, decision.Revoked)
	}
}

func (h *Handler) bootstrap(w http.ResponseWriter, r *http.Request, requestID string, authentication BootstrapAuthentication) {
	issued, err := h.bootstrapper.Bootstrap(r.Context(), authentication)
	if err != nil {
		writeAuthenticationProblem(w, requestID, err)
		return
	}
	response, err := sessionResponse(issued)
	if err != nil {
		w.Header().Set("Retry-After", "3")
		writeProblem(w, requestID, http.StatusServiceUnavailable, "temporarily_unavailable", "Temporarily unavailable")
		return
	}
	w.Header().Set("Content-Type", SessionMediaType)
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(response)
}

func (h *Handler) append(w http.ResponseWriter, r *http.Request, requestID string, admitted AdmittedRequest) {
	if !matchesVersionedMediaType(r.Header.Get("Content-Type"), EventMediaType) {
		writeProblem(w, requestID, http.StatusUnsupportedMediaType, "unsupported_media_type", "Unsupported media type")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEventBytes+1))
	if err != nil {
		writeProblem(w, requestID, http.StatusBadRequest, "invalid_request", "Invalid request")
		return
	}
	if len(body) > maxEventBytes {
		writeProblem(w, requestID, http.StatusRequestEntityTooLarge, "event_too_large", "Event too large")
		return
	}
	if len(body) == 0 {
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "invalid_event", "Invalid event")
		return
	}
	response, err := h.application.Append(r.Context(), admitted, body)
	if err != nil {
		writeApplicationProblem(w, requestID, err)
		return
	}
	if len(response.CanonicalReceipt) == 0 {
		writeApplicationProblem(w, requestID, relay.ErrSignaturePending)
		return
	}
	status := http.StatusCreated
	if response.Outcome == relay.AppendOutcomeDuplicate {
		status = http.StatusOK
	} else if response.Outcome != relay.AppendOutcomeAppended {
		writeApplicationProblem(w, requestID, relay.ErrInvalidArgument)
		return
	}
	w.Header().Set("Content-Type", ReceiptMediaType)
	w.WriteHeader(status)
	_, _ = w.Write(response.CanonicalReceipt)
}

func (h *Handler) replay(w http.ResponseWriter, r *http.Request, requestID string, admitted AdmittedRequest, after uint64, limit int) {
	if !matchesVersionedMediaType(r.Header.Get("Accept"), TranscriptBaseMediaType) {
		writeProblem(w, requestID, http.StatusNotAcceptable, "not_acceptable", "Representation not acceptable")
		return
	}
	page, err := h.application.Replay(r.Context(), ReplayRequest{AdmittedRequest: admitted, After: after, Limit: limit})
	if err != nil {
		writeApplicationProblem(w, requestID, err)
		return
	}
	if len(page) == 0 {
		writeApplicationProblem(w, requestID, errors.New("empty replay page"))
		return
	}
	w.Header().Set("Content-Type", TranscriptMediaType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
}

func (h *Handler) stream(w http.ResponseWriter, r *http.Request, requestID string, admitted AdmittedRequest, after uint64, revoked <-chan struct{}) {
	if mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Accept")); err != nil || !strings.EqualFold(mediaType, "text/event-stream") || len(parameters) != 0 {
		writeProblem(w, requestID, http.StatusNotAcceptable, "not_acceptable", "Representation not acceptable")
		return
	}
	items, err := h.application.Stream(r.Context(), ReplayRequest{AdmittedRequest: admitted, After: after, Limit: 1000})
	if err != nil {
		writeApplicationProblem(w, requestID, err)
		return
	}
	if items == nil {
		writeApplicationProblem(w, requestID, errors.New("missing stream"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeApplicationProblem(w, requestID, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.WriteHeader(http.StatusOK)
	if !h.writeStream(w, []byte("retry: 3000\n\n")) {
		return
	}
	flusher.Flush()

	heartbeat := time.NewTicker(h.config.HeartbeatInterval)
	defer heartbeat.Stop()
	lifetime := time.NewTimer(h.config.MaxStreamLifetime)
	defer lifetime.Stop()
	expected := after + 1
	for {
		if isRevoked(revoked) {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-revoked:
			return
		case <-lifetime.C:
			return
		case <-heartbeat.C:
			if isRevoked(revoked) {
				return
			}
			if !h.writeStream(w, []byte(": heartbeat\n\n")) {
				return
			}
			flusher.Flush()
		case item, open := <-items:
			if !open {
				return
			}
			if item.Err != nil {
				return
			}
			if isRevoked(revoked) {
				return
			}
			if item.IncompleteBoundary != nil {
				if *item.IncompleteBoundary != expected {
					return
				}
				payload := []byte(fmt.Sprintf("event: boundary-incomplete\ndata: {\"sequence\":\"%d\"}\n\n", *item.IncompleteBoundary))
				if h.writeStream(w, payload) {
					flusher.Flush()
				}
				return
			}
			if item.Record == nil || item.Record.Sequence != expected || len(item.Record.CanonicalRecord) == 0 || bytesContainLineBreak(item.Record.CanonicalRecord) {
				return
			}
			payload := []byte(fmt.Sprintf("id: %d\nevent: record\ndata: %s\n\n", item.Record.Sequence, item.Record.CanonicalRecord))
			if !h.writeStream(w, payload) {
				return
			}
			flusher.Flush()
			expected++
		}
	}
}

func isRevoked(revoked <-chan struct{}) bool {
	select {
	case <-revoked:
		return true
	default:
		return false
	}
}

func (h *Handler) writeStream(w http.ResponseWriter, payload []byte) bool {
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout))
	_, err := w.Write(payload)
	return err == nil
}

type parsedRoute struct {
	channel   relay.ChannelKey
	action    Action
	after     uint64
	limit     int
	bootstrap bool
}

func parseRoute(r *http.Request) (parsedRoute, error) {
	if len(r.RequestURI) > maxRequestTarget {
		return parsedRoute{}, relay.ErrInvalidArgument
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	if len(parts) == 3 && parts[0] == "coordination" && parts[1] == "v1" && parts[2] == "sessions" {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			return parsedRoute{}, relay.ErrInvalidArgument
		}
		return parsedRoute{bootstrap: true}, nil
	}
	if len(parts) != 7 || parts[0] != "coordination" || parts[1] != "v1" || parts[2] != "channels" || parts[4] != "transcripts" {
		return parsedRoute{}, relay.ErrInvalidArgument
	}
	channelID, err := strictSegment(parts[3])
	if err != nil {
		return parsedRoute{}, err
	}
	epoch, err := strictSegment(parts[5])
	if err != nil {
		return parsedRoute{}, err
	}
	if _, err := canonicalUint(epoch); err != nil {
		return parsedRoute{}, err
	}
	if utf8.RuneCountInString(channelID) > 256 {
		return parsedRoute{}, relay.ErrInvalidArgument
	}
	route := parsedRoute{channel: relay.ChannelKey{ChannelID: channelID, TranscriptEpoch: epoch}, limit: 100}
	switch parts[6] {
	case "events":
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			return parsedRoute{}, relay.ErrInvalidArgument
		}
		route.action = ActionPublish
	case "records":
		if r.Method != http.MethodGet {
			return parsedRoute{}, relay.ErrInvalidArgument
		}
		route.action = ActionReplay
		if err := parseReplayQuery(r.URL.Query(), &route); err != nil {
			return parsedRoute{}, err
		}
	case "stream":
		if r.Method != http.MethodGet || r.URL.RawQuery != "" {
			return parsedRoute{}, relay.ErrInvalidArgument
		}
		route.action = ActionWatch
		values := r.Header.Values("Last-Event-ID")
		if len(values) > 1 {
			return parsedRoute{}, relay.ErrInvalidArgument
		}
		if len(values) == 1 {
			route.after, err = canonicalUint(values[0])
			if err != nil {
				return parsedRoute{}, err
			}
		}
	default:
		return parsedRoute{}, relay.ErrInvalidArgument
	}
	return route, nil
}

func parseReplayQuery(values url.Values, route *parsedRoute) error {
	for key, entries := range values {
		if (key != "after" && key != "limit") || len(entries) != 1 {
			return relay.ErrInvalidArgument
		}
	}
	var err error
	if value := values.Get("after"); value != "" {
		route.after, err = canonicalUint(value)
		if err != nil {
			return err
		}
	}
	if value := values.Get("limit"); value != "" {
		parsed, err := canonicalUint(value)
		if err != nil || parsed < 1 || parsed > 1000 {
			return relay.ErrInvalidArgument
		}
		route.limit = int(parsed)
	}
	return nil
}

func strictSegment(raw string) (string, error) {
	decoded, err := url.PathUnescape(raw)
	if err != nil || decoded == "" || decoded == "." || decoded == ".." || strings.Contains(decoded, "/") || !utf8.ValidString(decoded) || url.PathEscape(decoded) != raw {
		return "", relay.ErrInvalidArgument
	}
	return decoded, nil
}

func canonicalUint(value string) (uint64, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, relay.ErrInvalidArgument
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, relay.ErrInvalidArgument
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > maxSafeInteger {
		return 0, relay.ErrInvalidArgument
	}
	return parsed, nil
}

func checkFraming(r *http.Request) error {
	count := 0
	for _, values := range r.Header {
		count += len(values)
	}
	if count > maxHeaders {
		return relay.ErrInvalidArgument
	}
	return nil
}

func dpopAuthentication(authorizationValues, proofValues []string) (string, string, error) {
	if len(authorizationValues) != 1 || len(authorizationValues[0]) > maxAuthorizationBytes || len(proofValues) != 1 || len(proofValues[0]) > maxDPoPProofBytes {
		return "", "", relay.ErrInvalidArgument
	}
	separator := strings.IndexByte(authorizationValues[0], ' ')
	if separator < 1 || !strings.EqualFold(authorizationValues[0][:separator], "DPoP") {
		return "", "", relay.ErrInvalidArgument
	}
	credential := authorizationValues[0][separator+1:]
	if credential == "" || strings.TrimSpace(credential) != credential || !validAuthorizationCredential(credential) || !validCompactProof(proofValues[0]) {
		return "", "", relay.ErrInvalidArgument
	}
	return credential, proofValues[0], nil
}

func validAuthorizationCredential(token string) bool {
	padding := false
	for _, character := range token {
		if character == '=' {
			padding = true
			continue
		}
		if padding || !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("-._~+/", character)) {
			return false
		}
	}
	return true
}

func validCompactProof(proof string) bool {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, character := range part {
			if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
				return false
			}
		}
	}
	return true
}

func checkBootstrapFraming(r *http.Request) error {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Type")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 || len(r.Header.Values("Cookie")) != 0 {
		return relay.ErrInvalidArgument
	}
	return nil
}

func parsePublicBaseURI(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" {
		return nil, relay.ErrInvalidArgument
	}
	if parsed.Path != "" && (parsed.Path[0] != '/' || strings.HasSuffix(parsed.Path, "/") || pathHasDotSegment(parsed.Path)) {
		return nil, relay.ErrInvalidArgument
	}
	return parsed, nil
}

func pathHasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func (h *Handler) publicTarget(escapedPath string) (string, error) {
	if escapedPath == "" || escapedPath[0] != '/' {
		return "", relay.ErrInvalidArgument
	}
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", relay.ErrInvalidArgument
	}
	target := *h.publicBase
	target.Path = strings.TrimSuffix(h.publicBase.Path, "/") + decodedPath
	target.RawPath = strings.TrimSuffix(h.publicBase.EscapedPath(), "/") + escapedPath
	if h.publicBase.Path == "" {
		target.RawPath = escapedPath
	}
	target.RawQuery = ""
	target.Fragment = ""
	return target.String(), nil
}

func setDPoPChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `DPoP algs="ES256"`)
}

func writeAuthenticationProblem(w http.ResponseWriter, requestID string, err error) {
	if errors.Is(err, ErrUnauthenticated) {
		setDPoPChallenge(w)
		writeProblem(w, requestID, http.StatusUnauthorized, "unauthenticated", "Authentication required")
		return
	}
	w.Header().Set("Retry-After", "3")
	writeProblem(w, requestID, http.StatusServiceUnavailable, "temporarily_unavailable", "Temporarily unavailable")
}

type sessionDocument struct {
	ExpiresAt             string `json:"expires_at"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	SessionEpoch          uint64 `json:"session_epoch"`
	SessionToken          string `json:"session_token"`
	SpecVersion           string `json:"specversion"`
	TokenType             string `json:"token_type"`
}

func sessionResponse(issued IssuedSession) ([]byte, error) {
	participant, err := uuid.Parse(issued.ParticipantInstanceID)
	if err != nil || participant.Version() != 7 || participant.String() != issued.ParticipantInstanceID || issued.SessionEpoch == 0 || issued.SessionEpoch > maxSafeInteger || !validSessionToken(issued.SessionToken) || issued.IssuedAt.Location() != time.UTC || issued.ExpiresAt.Location() != time.UTC || !issued.IssuedAt.Equal(issued.IssuedAt.Truncate(time.Millisecond)) || !issued.ExpiresAt.Equal(issued.ExpiresAt.Truncate(time.Millisecond)) || !issued.ExpiresAt.After(issued.IssuedAt) || issued.ExpiresAt.Sub(issued.IssuedAt) > 15*time.Minute {
		return nil, relay.ErrInvalidArgument
	}
	return json.Marshal(sessionDocument{
		ExpiresAt: issued.ExpiresAt.Format("2006-01-02T15:04:05.000Z"), ParticipantInstanceID: issued.ParticipantInstanceID,
		SessionEpoch: issued.SessionEpoch, SessionToken: issued.SessionToken, SpecVersion: "0.1", TokenType: "DPoP",
	})
}

func validSessionToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	for _, character := range token {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validIdentity(identity Identity) bool {
	participant, err := uuid.Parse(identity.ParticipantInstanceID)
	return err == nil && participant.Version() == 7 && participant.String() == identity.ParticipantInstanceID &&
		identity.TenantID != "" && identity.PrincipalID != "" && identity.SessionEpoch > 0 && identity.SessionEpoch <= maxSafeInteger
}

func validDecision(decision Decision) bool {
	return decision.Allowed && len(decision.CanonicalBinding) > 0 && decision.ACLPolicyVersion != "" && decision.ACLPolicyDigest != "" && decision.DecisionReceiptID != ""
}

func matchesVersionedMediaType(value, expected string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, expected) && len(parameters) == 1 && parameters["version"] == "0.1"
}

func bytesContainLineBreak(value []byte) bool {
	return strings.ContainsAny(string(value), "\r\n")
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(value[:])
}
