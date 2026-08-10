package previewprofile

import "time"

const (
	EffectANonceScopeDomain    = "yukh-suite-preview:effect-a:nonce-scope:v1\n"
	EffectALeaseResourceDomain = "yukh-suite-preview:effect-a:lease-resource:v1\n"
	EffectALeaseHolderDomain   = "yukh-suite-preview:effect-a:lease-holder:v1\n"
	EffectANonceValueDomain    = "yukh-suite-preview:effect-a:nonce:v1\n"
	EffectBNonceScopeDomain    = "yukh-suite-preview:effect-b:nonce-scope:v1\n"
	EffectBLeaseResourceDomain = "yukh-suite-preview:effect-b:lease-resource:v1\n"
	EffectBLeaseHolderDomain   = "yukh-suite-preview:effect-b:lease-holder:v1\n"
	EffectBNonceValueDomain    = "yukh-suite-preview:effect-b:nonce:v1\n"

	EffectAAbsentCapabilityDefinition   = "absent:rfc-0025:effect-a:mcp-capability-definition"
	EffectAAbsentProviderImplementation = "absent:rfc-0025:effect-a:mcp-provider-implementation"
)

type EffectANonceScope struct {
	ComponentIdempotencyKey         string   `json:"component_idempotency_key"`
	CoordinationTranscriptEpoch     uint64   `json:"coordination_transcript_epoch"`
	EnvironmentIdentity             string   `json:"environment_identity"`
	IntendedHolderIdentity          string   `json:"intended_holder_identity"`
	ItemIdentity                    string   `json:"item_identity"`
	MCPCapabilityDefinitionDigest   string   `json:"mcp_capability_definition_digest"`
	MCPProviderImplementationDigest string   `json:"mcp_provider_implementation_digest"`
	OperationScope                  []string `json:"operation_scope"`
	OperationSetDigest              string   `json:"operation_set_digest"`
	PolicyCommit                    string   `json:"policy_commit"`
	Postconditions                  []string `json:"postconditions"`
	PreconditionSnapshotIdentity    string   `json:"precondition_snapshot_identity"`
	PrimitivesRestoreEpoch          uint64   `json:"primitives_restore_epoch"`
	ProjectIdentity                 string   `json:"project_identity"`
	ProjectsProducerRelease         string   `json:"projects_producer_release"`
	ProtectedWorkflowIdentity       string   `json:"protected_workflow_identity"`
	RepositoryIdentity              string   `json:"repository_identity"`
	VerifierIdentity                string   `json:"verifier_identity"`
}

type EffectAPreLease struct {
	EffectANonceScope
	NonceScopeDigest string `json:"nonce_scope_digest"`
}

type EffectBNonceScope struct {
	ComponentIdempotencyKey         string   `json:"component_idempotency_key"`
	CoordinationTranscriptEpoch     uint64   `json:"coordination_transcript_epoch"`
	EnvironmentIdentity             string   `json:"environment_identity"`
	IntendedHolderIdentity          string   `json:"intended_holder_identity"`
	ItemIdentity                    string   `json:"item_identity"`
	MCPCapabilityDefinitionDigest   string   `json:"mcp_capability_definition_digest"`
	MCPProducerRelease              string   `json:"mcp_producer_release"`
	MCPProviderImplementationDigest string   `json:"mcp_provider_implementation_digest"`
	OperationScope                  []string `json:"operation_scope"`
	OperationSetDigest              string   `json:"operation_set_digest"`
	PolicyCommit                    string   `json:"policy_commit"`
	Postconditions                  []string `json:"postconditions"`
	PreconditionSnapshotIdentity    string   `json:"precondition_snapshot_identity"`
	PrimitivesRestoreEpoch          uint64   `json:"primitives_restore_epoch"`
	ProjectIdentity                 string   `json:"project_identity"`
	ProjectsProducerRelease         string   `json:"projects_producer_release"`
	ProtectedWorkflowIdentity       string   `json:"protected_workflow_identity"`
	RepositoryIdentity              string   `json:"repository_identity"`
	VerifierIdentity                string   `json:"verifier_identity"`
}

type EffectBPreLease struct {
	EffectBNonceScope
	NonceScopeDigest string `json:"nonce_scope_digest"`
}

type EffectABinding struct {
	ApprovalExpiresAt               string   `json:"approval_expires_at"`
	ApprovalIssuedAt                string   `json:"approval_issued_at"`
	ApprovalIssuer                  string   `json:"approval_issuer"`
	ApprovalNonce                   string   `json:"approval_nonce"`
	ApprovalSubject                 string   `json:"approval_subject"`
	ComponentIdempotencyKey         string   `json:"component_idempotency_key"`
	CoordinationTranscriptEpoch     uint64   `json:"coordination_transcript_epoch"`
	EnvironmentIdentity             string   `json:"environment_identity"`
	FencingToken                    uint64   `json:"fencing_token"`
	ItemIdentity                    string   `json:"item_identity"`
	LeaseExpiresAt                  string   `json:"lease_expires_at"`
	LeaseHolderIdentity             string   `json:"lease_holder_identity"`
	LeaseResourceIdentity           string   `json:"lease_resource_identity"`
	MCPCapabilityDefinitionDigest   string   `json:"mcp_capability_definition_digest"`
	MCPProviderImplementationDigest string   `json:"mcp_provider_implementation_digest"`
	MinimumRemainingLeaseMillis     uint64   `json:"minimum_remaining_lease_millis"`
	NonceScopeDigest                string   `json:"nonce_scope_digest"`
	OperationScope                  []string `json:"operation_scope"`
	OperationSetDigest              string   `json:"operation_set_digest"`
	PlanDigest                      string   `json:"plan_digest"`
	PlanID                          string   `json:"plan_id"`
	PolicyCommit                    string   `json:"policy_commit"`
	Postconditions                  []string `json:"postconditions"`
	PreconditionSnapshotIdentity    string   `json:"precondition_snapshot_identity"`
	PrimitivesRestoreEpoch          uint64   `json:"primitives_restore_epoch"`
	ProjectIdentity                 string   `json:"project_identity"`
	ProjectsProducerRelease         string   `json:"projects_producer_release"`
	ProtectedWorkflowIdentity       string   `json:"protected_workflow_identity"`
	RepositoryIdentity              string   `json:"repository_identity"`
	VerifierIdentity                string   `json:"verifier_identity"`
}

type EffectBBinding struct {
	ApprovalExpiresAt               string   `json:"approval_expires_at"`
	ApprovalIssuedAt                string   `json:"approval_issued_at"`
	ApprovalIssuer                  string   `json:"approval_issuer"`
	ApprovalNonce                   string   `json:"approval_nonce"`
	ApprovalSubject                 string   `json:"approval_subject"`
	ComponentIdempotencyKey         string   `json:"component_idempotency_key"`
	CoordinationTranscriptEpoch     uint64   `json:"coordination_transcript_epoch"`
	EnvironmentIdentity             string   `json:"environment_identity"`
	FencingToken                    uint64   `json:"fencing_token"`
	ItemIdentity                    string   `json:"item_identity"`
	LeaseExpiresAt                  string   `json:"lease_expires_at"`
	LeaseHolderIdentity             string   `json:"lease_holder_identity"`
	LeaseResourceIdentity           string   `json:"lease_resource_identity"`
	MCPCapabilityDefinitionDigest   string   `json:"mcp_capability_definition_digest"`
	MCPProducerRelease              string   `json:"mcp_producer_release"`
	MCPProviderImplementationDigest string   `json:"mcp_provider_implementation_digest"`
	MinimumRemainingLeaseMillis     uint64   `json:"minimum_remaining_lease_millis"`
	NonceScopeDigest                string   `json:"nonce_scope_digest"`
	OperationScope                  []string `json:"operation_scope"`
	OperationSetDigest              string   `json:"operation_set_digest"`
	PlanDigest                      string   `json:"plan_digest"`
	PlanID                          string   `json:"plan_id"`
	PolicyCommit                    string   `json:"policy_commit"`
	Postconditions                  []string `json:"postconditions"`
	PreconditionSnapshotIdentity    string   `json:"precondition_snapshot_identity"`
	PrimitivesRestoreEpoch          uint64   `json:"primitives_restore_epoch"`
	ProjectIdentity                 string   `json:"project_identity"`
	ProjectsProducerRelease         string   `json:"projects_producer_release"`
	ProtectedWorkflowIdentity       string   `json:"protected_workflow_identity"`
	RepositoryIdentity              string   `json:"repository_identity"`
	VerifierIdentity                string   `json:"verifier_identity"`
}

type NonceRequest struct {
	Epoch       uint64 `json:"epoch"`
	ExpiresAt   string `json:"expires_at"`
	ScopeDigest string `json:"scope_digest"`
	ValueDigest string `json:"value_digest"`
}

func CanonicalEffectANonceScope(value EffectANonceScope) ([]byte, error) {
	if validateEffectANonceScope(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func CanonicalEffectBNonceScope(value EffectBNonceScope) ([]byte, error) {
	if validateEffectBNonceScope(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func DeriveEffectANonceScopeDigest(value EffectANonceScope) (string, error) {
	body, err := CanonicalEffectANonceScope(value)
	if err != nil {
		return "", err
	}
	return derive(EffectANonceScopeDomain, body), nil
}

func DeriveEffectBNonceScopeDigest(value EffectBNonceScope) (string, error) {
	body, err := CanonicalEffectBNonceScope(value)
	if err != nil {
		return "", err
	}
	return derive(EffectBNonceScopeDomain, body), nil
}

func CanonicalEffectAPreLease(value EffectAPreLease) ([]byte, error) {
	expected, err := DeriveEffectANonceScopeDigest(value.EffectANonceScope)
	if err != nil || value.NonceScopeDigest != expected {
		return nil, ErrScopeMismatch
	}
	return canonical(value)
}

func CanonicalEffectBPreLease(value EffectBPreLease) ([]byte, error) {
	expected, err := DeriveEffectBNonceScopeDigest(value.EffectBNonceScope)
	if err != nil || value.NonceScopeDigest != expected {
		return nil, ErrScopeMismatch
	}
	return canonical(value)
}

func DeriveEffectALeaseResource(value EffectAPreLease) (string, error) {
	body, err := CanonicalEffectAPreLease(value)
	if err != nil {
		return "", err
	}
	return derive(EffectALeaseResourceDomain, body), nil
}

func DeriveEffectALeaseHolder(value EffectAPreLease) (string, error) {
	body, err := CanonicalEffectAPreLease(value)
	if err != nil {
		return "", err
	}
	return derive(EffectALeaseHolderDomain, body), nil
}

func DeriveEffectBLeaseResource(value EffectBPreLease) (string, error) {
	body, err := CanonicalEffectBPreLease(value)
	if err != nil {
		return "", err
	}
	return derive(EffectBLeaseResourceDomain, body), nil
}

func DeriveEffectBLeaseHolder(value EffectBPreLease) (string, error) {
	body, err := CanonicalEffectBPreLease(value)
	if err != nil {
		return "", err
	}
	return derive(EffectBLeaseHolderDomain, body), nil
}

func CanonicalEffectABinding(value EffectABinding) ([]byte, error) {
	if validateEffectABinding(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func CanonicalEffectBBinding(value EffectBBinding) ([]byte, error) {
	if validateEffectBBinding(value) != nil {
		return nil, ErrInvalid
	}
	return canonical(value)
}

func DeriveEffectANonceValue(value EffectABinding) (string, error) {
	body, err := CanonicalEffectABinding(value)
	if err != nil {
		return "", err
	}
	return derive(EffectANonceValueDomain, body), nil
}

func DeriveEffectBNonceValue(value EffectBBinding) (string, error) {
	body, err := CanonicalEffectBBinding(value)
	if err != nil {
		return "", err
	}
	return derive(EffectBNonceValueDomain, body), nil
}

func ValidateEffectAAuthority(preLease EffectAPreLease, binding EffectABinding) error {
	resource, resourceErr := DeriveEffectALeaseResource(preLease)
	holder, holderErr := DeriveEffectALeaseHolder(preLease)
	if resourceErr != nil || holderErr != nil || validateEffectABinding(binding) != nil {
		return ErrInvalid
	}
	if preLease.NonceScopeDigest != binding.NonceScopeDigest {
		return ErrScopeMismatch
	}
	if resource != binding.LeaseResourceIdentity || holder != binding.LeaseHolderIdentity ||
		!sameEffectAFields(preLease, binding) {
		return ErrInvalid
	}
	return nil
}

func ValidateEffectBAuthority(preLease EffectBPreLease, binding EffectBBinding) error {
	resource, resourceErr := DeriveEffectBLeaseResource(preLease)
	holder, holderErr := DeriveEffectBLeaseHolder(preLease)
	if resourceErr != nil || holderErr != nil || validateEffectBBinding(binding) != nil {
		return ErrInvalid
	}
	if preLease.NonceScopeDigest != binding.NonceScopeDigest {
		return ErrScopeMismatch
	}
	if resource != binding.LeaseResourceIdentity || holder != binding.LeaseHolderIdentity ||
		!sameEffectBFields(preLease, binding) {
		return ErrInvalid
	}
	return nil
}

func ValidateEffectANonceRequest(preLease EffectAPreLease, binding EffectABinding, request NonceRequest) error {
	if !validPositive(request.Epoch) || !validRawDigest(request.ScopeDigest) ||
		!validRawDigest(request.ValueDigest) {
		return ErrInvalid
	}
	if err := ValidateEffectAAuthority(preLease, binding); err != nil {
		if err == ErrScopeMismatch {
			return ErrScopeMismatch
		}
		return ErrInvalid
	}
	expectedValue, err := DeriveEffectANonceValue(binding)
	if err != nil {
		return ErrInvalid
	}
	if request.ScopeDigest != binding.NonceScopeDigest {
		return ErrScopeMismatch
	}
	if request.ValueDigest != expectedValue || request.Epoch != binding.PrimitivesRestoreEpoch ||
		request.ExpiresAt != binding.ApprovalExpiresAt {
		return ErrInvalid
	}
	return nil
}

func ValidateEffectBNonceRequest(preLease EffectBPreLease, binding EffectBBinding, request NonceRequest) error {
	if !validPositive(request.Epoch) || !validRawDigest(request.ScopeDigest) ||
		!validRawDigest(request.ValueDigest) {
		return ErrInvalid
	}
	if err := ValidateEffectBAuthority(preLease, binding); err != nil {
		if err == ErrScopeMismatch {
			return ErrScopeMismatch
		}
		return ErrInvalid
	}
	expectedValue, err := DeriveEffectBNonceValue(binding)
	if err != nil {
		return ErrInvalid
	}
	if request.ScopeDigest != binding.NonceScopeDigest {
		return ErrScopeMismatch
	}
	if request.ValueDigest != expectedValue || request.Epoch != binding.PrimitivesRestoreEpoch ||
		request.ExpiresAt != binding.ApprovalExpiresAt {
		return ErrInvalid
	}
	return nil
}

func ValidateIndependentEffects(
	aPreLease EffectAPreLease,
	aBinding EffectABinding,
	bPreLease EffectBPreLease,
	bBinding EffectBBinding,
) error {
	if ValidateEffectAAuthority(aPreLease, aBinding) != nil ||
		ValidateEffectBAuthority(bPreLease, bBinding) != nil {
		return ErrInvalid
	}
	aValue, _ := DeriveEffectANonceValue(aBinding)
	bValue, _ := DeriveEffectBNonceValue(bBinding)
	if aBinding.PreconditionSnapshotIdentity == bBinding.PreconditionSnapshotIdentity ||
		aBinding.NonceScopeDigest == bBinding.NonceScopeDigest ||
		aValue == bValue ||
		aBinding.LeaseResourceIdentity == bBinding.LeaseResourceIdentity ||
		aBinding.LeaseHolderIdentity == bBinding.LeaseHolderIdentity ||
		aBinding.FencingToken == bBinding.FencingToken ||
		aBinding.PlanID == bBinding.PlanID ||
		aBinding.PlanDigest == bBinding.PlanDigest ||
		aBinding.ApprovalNonce == bBinding.ApprovalNonce ||
		aBinding.ComponentIdempotencyKey == bBinding.ComponentIdempotencyKey ||
		aBinding.VerifierIdentity == bBinding.VerifierIdentity ||
		aBinding.PrimitivesRestoreEpoch == bBinding.PrimitivesRestoreEpoch {
		return ErrAuthorityReuse
	}
	if aBinding.ItemIdentity == bBinding.ItemIdentity && listsOverlap(aBinding.OperationScope, bBinding.OperationScope) {
		return ErrAuthorityReuse
	}
	return nil
}

func validateEffectANonceScope(value EffectANonceScope) error {
	if !validProjectionFields(
		value.RepositoryIdentity, value.ProjectIdentity, value.ItemIdentity,
		value.PolicyCommit, value.ProjectsProducerRelease,
		value.PreconditionSnapshotIdentity, value.OperationSetDigest,
		value.EnvironmentIdentity, value.ProtectedWorkflowIdentity,
		value.ComponentIdempotencyKey, value.CoordinationTranscriptEpoch,
		value.PrimitivesRestoreEpoch, value.IntendedHolderIdentity,
		value.VerifierIdentity, value.OperationScope, value.Postconditions,
	) || value.MCPCapabilityDefinitionDigest != EffectAAbsentCapabilityDefinition ||
		value.MCPProviderImplementationDigest != EffectAAbsentProviderImplementation {
		return ErrInvalid
	}
	return nil
}

func validateEffectBNonceScope(value EffectBNonceScope) error {
	if !validProjectionFields(
		value.RepositoryIdentity, value.ProjectIdentity, value.ItemIdentity,
		value.PolicyCommit, value.ProjectsProducerRelease,
		value.PreconditionSnapshotIdentity, value.OperationSetDigest,
		value.EnvironmentIdentity, value.ProtectedWorkflowIdentity,
		value.ComponentIdempotencyKey, value.CoordinationTranscriptEpoch,
		value.PrimitivesRestoreEpoch, value.IntendedHolderIdentity,
		value.VerifierIdentity, value.OperationScope, value.Postconditions,
	) || !validDigest(value.MCPProducerRelease) ||
		!validDigest(value.MCPCapabilityDefinitionDigest) ||
		!validDigest(value.MCPProviderImplementationDigest) {
		return ErrInvalid
	}
	return nil
}

func validateEffectABinding(value EffectABinding) error {
	if !validBindingFields(
		value.RepositoryIdentity, value.ProjectIdentity, value.ItemIdentity,
		value.PolicyCommit, value.ProjectsProducerRelease,
		value.PreconditionSnapshotIdentity, value.PlanID, value.PlanDigest,
		value.OperationSetDigest, value.EnvironmentIdentity,
		value.ProtectedWorkflowIdentity, value.ApprovalIssuer,
		value.ApprovalSubject, value.ApprovalNonce, value.NonceScopeDigest,
		value.ComponentIdempotencyKey, value.CoordinationTranscriptEpoch,
		value.PrimitivesRestoreEpoch, value.LeaseResourceIdentity,
		value.LeaseHolderIdentity, value.FencingToken,
		value.MinimumRemainingLeaseMillis, value.VerifierIdentity,
		value.OperationScope, value.Postconditions, value.ApprovalIssuedAt,
		value.ApprovalExpiresAt, value.LeaseExpiresAt,
	) || value.MCPCapabilityDefinitionDigest != EffectAAbsentCapabilityDefinition ||
		value.MCPProviderImplementationDigest != EffectAAbsentProviderImplementation {
		return ErrInvalid
	}
	return nil
}

func validateEffectBBinding(value EffectBBinding) error {
	if !validBindingFields(
		value.RepositoryIdentity, value.ProjectIdentity, value.ItemIdentity,
		value.PolicyCommit, value.ProjectsProducerRelease,
		value.PreconditionSnapshotIdentity, value.PlanID, value.PlanDigest,
		value.OperationSetDigest, value.EnvironmentIdentity,
		value.ProtectedWorkflowIdentity, value.ApprovalIssuer,
		value.ApprovalSubject, value.ApprovalNonce, value.NonceScopeDigest,
		value.ComponentIdempotencyKey, value.CoordinationTranscriptEpoch,
		value.PrimitivesRestoreEpoch, value.LeaseResourceIdentity,
		value.LeaseHolderIdentity, value.FencingToken,
		value.MinimumRemainingLeaseMillis, value.VerifierIdentity,
		value.OperationScope, value.Postconditions, value.ApprovalIssuedAt,
		value.ApprovalExpiresAt, value.LeaseExpiresAt,
	) || !validDigest(value.MCPProducerRelease) ||
		!validDigest(value.MCPCapabilityDefinitionDigest) ||
		!validDigest(value.MCPProviderImplementationDigest) {
		return ErrInvalid
	}
	return nil
}

func validProjectionFields(
	repository, project, item, policyCommit, projectsRelease, snapshot,
	operationSet, environment, workflow, idempotencyKey string,
	transcriptEpoch, restoreEpoch uint64,
	holder, verifier string,
	operations, postconditions []string,
) bool {
	return validIdentifier(repository) && validIdentifier(project) &&
		validIdentifier(item) && validCommit(policyCommit) &&
		validDigest(projectsRelease) && validDigest(snapshot) &&
		validDigest(operationSet) && validIdentifier(environment) &&
		validIdentifier(workflow) && validIdentifier(idempotencyKey) &&
		validPositive(transcriptEpoch) && validPositive(restoreEpoch) &&
		validIdentifier(holder) && validIdentifier(verifier) &&
		validIdentifiers(operations, 1, 64) &&
		validIdentifiers(postconditions, 1, 64)
}

func validBindingFields(
	repository, project, item, policyCommit, projectsRelease, snapshot,
	planID, planDigest, operationSet, environment, workflow, approvalIssuer,
	approvalSubject, approvalNonce, nonceScope, idempotencyKey string,
	transcriptEpoch, restoreEpoch uint64,
	leaseResource, leaseHolder string,
	fencingToken, minimumRemaining uint64,
	verifier string,
	operations, postconditions []string,
	approvalIssuedAt, approvalExpiresAt, leaseExpiresAt string,
) bool {
	issued, issuedOK := validTime(approvalIssuedAt)
	expires, expiresOK := validTime(approvalExpiresAt)
	leaseExpires, leaseOK := validTime(leaseExpiresAt)
	return validProjectionFields(
		repository, project, item, policyCommit, projectsRelease, snapshot,
		operationSet, environment, workflow, idempotencyKey,
		transcriptEpoch, restoreEpoch, leaseHolder, verifier,
		operations, postconditions,
	) && validIdentifier(planID) && validDigest(planDigest) &&
		validIdentifier(approvalIssuer) && validIdentifier(approvalSubject) &&
		validIdentifier(approvalNonce) && validRawDigest(nonceScope) &&
		validRawDigest(leaseResource) && validRawDigest(leaseHolder) &&
		validPositive(fencingToken) && validPositive(minimumRemaining) &&
		minimumRemaining <= 4*60*60*1000 &&
		issuedOK && expiresOK && leaseOK && expires.After(issued) &&
		leaseExpires.After(issued) &&
		leaseExpires.Sub(issued) >= time.Duration(minimumRemaining)*time.Millisecond
}

func sameEffectAFields(preLease EffectAPreLease, binding EffectABinding) bool {
	return preLease.RepositoryIdentity == binding.RepositoryIdentity &&
		preLease.ProjectIdentity == binding.ProjectIdentity &&
		preLease.ItemIdentity == binding.ItemIdentity &&
		equalLists(preLease.OperationScope, binding.OperationScope) &&
		preLease.PolicyCommit == binding.PolicyCommit &&
		preLease.ProjectsProducerRelease == binding.ProjectsProducerRelease &&
		preLease.PreconditionSnapshotIdentity == binding.PreconditionSnapshotIdentity &&
		preLease.OperationSetDigest == binding.OperationSetDigest &&
		preLease.MCPCapabilityDefinitionDigest == binding.MCPCapabilityDefinitionDigest &&
		preLease.MCPProviderImplementationDigest == binding.MCPProviderImplementationDigest &&
		preLease.EnvironmentIdentity == binding.EnvironmentIdentity &&
		preLease.ProtectedWorkflowIdentity == binding.ProtectedWorkflowIdentity &&
		preLease.ComponentIdempotencyKey == binding.ComponentIdempotencyKey &&
		preLease.CoordinationTranscriptEpoch == binding.CoordinationTranscriptEpoch &&
		preLease.PrimitivesRestoreEpoch == binding.PrimitivesRestoreEpoch &&
		preLease.VerifierIdentity == binding.VerifierIdentity &&
		equalLists(preLease.Postconditions, binding.Postconditions)
}

func sameEffectBFields(preLease EffectBPreLease, binding EffectBBinding) bool {
	return preLease.RepositoryIdentity == binding.RepositoryIdentity &&
		preLease.ProjectIdentity == binding.ProjectIdentity &&
		preLease.ItemIdentity == binding.ItemIdentity &&
		equalLists(preLease.OperationScope, binding.OperationScope) &&
		preLease.PolicyCommit == binding.PolicyCommit &&
		preLease.ProjectsProducerRelease == binding.ProjectsProducerRelease &&
		preLease.MCPProducerRelease == binding.MCPProducerRelease &&
		preLease.PreconditionSnapshotIdentity == binding.PreconditionSnapshotIdentity &&
		preLease.OperationSetDigest == binding.OperationSetDigest &&
		preLease.MCPCapabilityDefinitionDigest == binding.MCPCapabilityDefinitionDigest &&
		preLease.MCPProviderImplementationDigest == binding.MCPProviderImplementationDigest &&
		preLease.EnvironmentIdentity == binding.EnvironmentIdentity &&
		preLease.ProtectedWorkflowIdentity == binding.ProtectedWorkflowIdentity &&
		preLease.ComponentIdempotencyKey == binding.ComponentIdempotencyKey &&
		preLease.CoordinationTranscriptEpoch == binding.CoordinationTranscriptEpoch &&
		preLease.PrimitivesRestoreEpoch == binding.PrimitivesRestoreEpoch &&
		preLease.VerifierIdentity == binding.VerifierIdentity &&
		equalLists(preLease.Postconditions, binding.Postconditions)
}

func equalLists(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func listsOverlap(left, right []string) bool {
	seen := make(map[string]struct{}, len(left))
	for _, value := range left {
		seen[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := seen[value]; exists {
			return true
		}
	}
	return false
}
