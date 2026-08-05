package clientevent_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nomed/yukh-coordination/internal/clientevent"
	"github.com/nomed/yukh-coordination/internal/relay/protocol"
)

func conversationBuilder(t *testing.T) *clientevent.Builder {
	t.Helper()
	sequence := 200
	builder, err := clientevent.New(clientevent.Config{
		ChannelURI:  "https://coord.example/channels/project-release",
		SourceURI:   "urn:yukh:source:conversation-test",
		Participant: clientevent.Participant{ID: "agent:reviewer", Kind: "agent"},
		Now:         func() time.Time { return time.Date(2026, 8, 5, 16, 0, 0, 0, time.UTC) },
		NewID: func() (string, error) {
			sequence++
			return fmt.Sprintf("019c6f5b-7c00-7000-8000-%012d", sequence), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func TestBuildsQuestionReviewAndHandoffFamilies(t *testing.T) {
	builder := conversationBuilder(t)
	work := "https://github.com/nomed/yukh-coordination/issues/7"
	claimID := "019c6f5b-7c00-7000-8000-000000000301"
	claimEvent := "019c6f5b-7c00-7000-8000-000000000302"
	recipient := "019c6f5b-7c00-7000-8000-000000000303"

	question, err := builder.Question(clientevent.Question{WorkURI: work, Body: "Is the receipt verified?", RequestedFrom: []string{"review"}, ResponseRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := builder.Answer(clientevent.Answer{WorkURI: work, CorrelationID: question.EventID, QuestionEventID: question.EventID, Body: "Yes", Disposition: "answered"})
	if err != nil {
		t.Fatal(err)
	}
	review, err := builder.ReviewRequest(clientevent.ReviewRequest{WorkURI: work, ClaimID: claimID, Subject: "client flow", Criteria: []string{"valid receipt"}, IndependenceRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := builder.Verdict(clientevent.Verdict{WorkURI: work, CorrelationID: review.EventID, ReviewEventID: review.EventID, EvidenceSetDigest: review.EvidenceSetDigest, Outcome: "pass", Summary: "verified", Findings: []string{}, ReviewerIndependent: true})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := builder.HandoffOffer(clientevent.HandoffOffer{WorkURI: work, CorrelationID: claimEvent, CausationID: claimEvent, ClaimID: claimID, Generation: "0", ParentClaimEventID: claimEvent, ToParticipantInstanceID: recipient, Boundary: "continue CLI", NextAction: "implement commands", UnresolvedRisks: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	accept, err := builder.HandoffAccept(clientevent.HandoffAccept{WorkURI: work, CorrelationID: claimEvent, OfferEventID: offer.EventID, SourceClaimEventID: claimEvent, HandoffID: offer.HandoffID, ClaimID: claimID, Generation: "0", BoundaryDigest: offer.BoundaryDigest, EvidenceSetDigest: offer.EvidenceSetDigest})
	if err != nil {
		t.Fatal(err)
	}
	release, err := builder.Release(clientevent.Release{WorkURI: work, CorrelationID: claimEvent, CausationID: claimEvent, ClaimID: claimID, Generation: "0", ParentClaimEventID: claimEvent, Outcome: "superseded", Reason: "handoff accepted"})
	if err != nil {
		t.Fatal(err)
	}
	leave, err := builder.Leave(clientevent.Leave{Reason: "handoff complete"})
	if err != nil {
		t.Fatal(err)
	}

	validator, err := protocol.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range []clientevent.Result{question, answer, review, verdict, offer, accept, release, leave} {
		if _, err := validator.Validate(result.Canonical); err != nil {
			t.Fatalf("invalid event %s: %v", result.Canonical, err)
		}
	}
	if offer.HandoffID == "" || answer.EventID == question.EventID || verdict.EventID == review.EventID {
		t.Fatal("generated identifiers are not distinct")
	}
}

func TestConversationBuildersRejectIncompleteBindings(t *testing.T) {
	builder := conversationBuilder(t)
	if _, err := builder.Answer(clientevent.Answer{WorkURI: "https://example.test/work", Body: "missing bindings", Disposition: "answered"}); err == nil {
		t.Fatal("answer without correlation was accepted")
	}
	if _, err := builder.HandoffOffer(clientevent.HandoffOffer{WorkURI: "https://example.test/work"}); err == nil {
		t.Fatal("empty handoff was accepted")
	}
}
