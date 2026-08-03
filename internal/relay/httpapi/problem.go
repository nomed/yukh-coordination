package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nomed/yukh-coordination/internal/relay"
)

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func writeApplicationProblem(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, relay.ErrEventIDCollision), errors.Is(err, relay.ErrSignatureCollision):
		writeProblem(w, requestID, http.StatusConflict, "conflict", "Conflict")
	case errors.Is(err, relay.ErrInvalidArgument):
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "invalid_event", "Invalid event")
	case errors.Is(err, relay.ErrResourceLimit):
		writeProblem(w, requestID, http.StatusTooManyRequests, "resource_limit", "Resource limit")
	case errors.Is(err, relay.ErrTransitionConflict):
		writeProblem(w, requestID, http.StatusUnprocessableEntity, "transition_precondition_failed", "Transition precondition failed")
	case errors.Is(err, relay.ErrSignaturePending), errors.Is(err, relay.ErrCommitIndeterminate):
		w.Header().Set("Retry-After", "3")
		writeProblem(w, requestID, http.StatusServiceUnavailable, "temporarily_unavailable", "Temporarily unavailable")
	case errors.Is(err, relay.ErrChannelNotFound), errors.Is(err, relay.ErrEventNotFound), errors.Is(err, relay.ErrReceiptNotFound):
		writeProblem(w, requestID, http.StatusNotFound, "resource_unavailable", "Resource unavailable")
	default:
		writeProblem(w, requestID, http.StatusServiceUnavailable, "temporarily_unavailable", "Temporarily unavailable")
	}
}

func writeProblem(w http.ResponseWriter, requestID string, status int, code, title string) {
	w.Header().Set("Content-Type", ProblemMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{
		Type: "urn:yukh:coordination:problem:" + code, Title: title,
		Status: status, Code: code, RequestID: requestID,
	})
}
