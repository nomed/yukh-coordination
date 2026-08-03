package client

import (
	"encoding/json"
	"sort"
)

type ClaimView struct {
	ClaimID               string `json:"claim_id"`
	Generation            string `json:"generation"`
	ClaimEventID          string `json:"claim_event_id"`
	ParticipantInstanceID string `json:"participant_instance_id"`
	LatestProgress        string `json:"latest_progress,omitempty"`
}

type WorkView struct {
	SpecVersion       string      `json:"specversion"`
	WorkURI           string      `json:"work_uri"`
	State             string      `json:"state"`
	HighWaterSequence uint64      `json:"high_water_sequence"`
	Completeness      string      `json:"completeness"`
	Claims            []ClaimView `json:"claims"`
	HandoffOfferIDs   []string    `json:"handoff_offer_ids"`
}

type claimState struct {
	view   ClaimView
	active bool
	last   string
	offers map[string]bool
}

func Inspect(replay ReplayResult, workURI string) (WorkView, error) {
	if workURI == "" {
		return WorkView{}, ErrInvalidInput
	}
	claims := map[string]*claimState{}
	for _, record := range replay.Records {
		var event struct {
			ID, Type string
			Work     *struct {
				URI string `json:"uri"`
			} `json:"work"`
			Data map[string]any `json:"data"`
		}
		var receipt struct {
			ParticipantInstanceID string `json:"participant_instance_id"`
		}
		if json.Unmarshal(record.Event, &event) != nil || json.Unmarshal(record.Receipt, &receipt) != nil || event.Work == nil || event.Work.URI != workURI {
			continue
		}
		claimID, _ := event.Data["claim_id"].(string)
		generation, _ := event.Data["generation"].(string)
		key := claimID + "\x00" + generation
		switch event.Type {
		case "claim":
			claims[key] = &claimState{view: ClaimView{ClaimID: claimID, Generation: generation, ClaimEventID: event.ID, ParticipantInstanceID: receipt.ParticipantInstanceID}, active: true, last: event.ID, offers: map[string]bool{}}
		case "progress", "handoff_offer", "release":
			claim := claims[key]
			if claim == nil || !claim.active {
				continue
			}
			parent, _ := event.Data["parent_claim_event_id"].(string)
			if parent != claim.last {
				continue
			}
			claim.last = event.ID
			if event.Type == "progress" {
				claim.view.LatestProgress, _ = event.Data["summary"].(string)
			}
			if event.Type == "handoff_offer" {
				if id, ok := event.Data["handoff_id"].(string); ok {
					claim.offers[id] = true
				}
			}
			if event.Type == "release" {
				claim.active = false
				claim.offers = map[string]bool{}
			}
		case "handoff_accept":
			for _, claim := range claims {
				if claim.active {
					claim.offers = map[string]bool{}
				}
			}
		}
	}
	view := WorkView{SpecVersion: "0.1", WorkURI: workURI, State: "unclaimed", HighWaterSequence: replay.HighWaterSequence, Completeness: replay.Completeness, Claims: []ClaimView{}, HandoffOfferIDs: []string{}}
	for _, claim := range claims {
		if claim.active {
			view.Claims = append(view.Claims, claim.view)
			for id := range claim.offers {
				view.HandoffOfferIDs = append(view.HandoffOfferIDs, id)
			}
		}
	}
	sort.Slice(view.Claims, func(i, j int) bool { return view.Claims[i].ClaimID < view.Claims[j].ClaimID })
	sort.Strings(view.HandoffOfferIDs)
	switch len(view.Claims) {
	case 0:
		if len(claims) > 0 {
			view.State = "released"
		}
	case 1:
		if len(view.HandoffOfferIDs) > 0 {
			view.State = "handoff_offered"
		} else {
			view.State = "claimed"
		}
	default:
		view.State = "conflicting"
		view.HandoffOfferIDs = []string{}
	}
	if replay.Completeness != "complete" {
		return view, ErrIncomplete
	}
	return view, nil
}
