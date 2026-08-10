package previewprofile

type TeardownState string

const (
	TeardownRequested          TeardownState = "requested"
	TeardownAdmissionClosed    TeardownState = "admission_closed"
	TeardownEvidenceFrozen     TeardownState = "evidence_frozen"
	TeardownCredentialsRevoked TeardownState = "credentials_revoked"
	TeardownProcessesStopped   TeardownState = "processes_stopped"
	TeardownStorageRemoved     TeardownState = "storage_removed"
	TeardownAbsenceVerified    TeardownState = "absence_verified"
	TeardownCompleted          TeardownState = "completed"
	TeardownIncomplete         TeardownState = "teardown_incomplete"
)

var teardownSequence = [...]TeardownState{
	TeardownRequested,
	TeardownAdmissionClosed,
	TeardownEvidenceFrozen,
	TeardownCredentialsRevoked,
	TeardownProcessesStopped,
	TeardownStorageRemoved,
	TeardownAbsenceVerified,
	TeardownCompleted,
}

func TeardownStates() []TeardownState {
	result := make([]TeardownState, 0, len(teardownSequence)+1)
	result = append(result, teardownSequence[:]...)
	return append(result, TeardownIncomplete)
}

func ValidateTeardownTransition(current, next TeardownState) error {
	for index := 0; index < len(teardownSequence)-1; index++ {
		if current == teardownSequence[index] && next == teardownSequence[index+1] {
			return nil
		}
	}
	return ErrInvalidTransition
}

func FailTeardown(current TeardownState) (TeardownState, error) {
	for _, state := range teardownSequence[:len(teardownSequence)-1] {
		if current == state {
			return TeardownIncomplete, nil
		}
	}
	return "", ErrInvalidTransition
}
