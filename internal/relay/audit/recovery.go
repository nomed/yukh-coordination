package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"os"
	"time"

	"github.com/nomed/yukh-coordination/internal/relay/identity"
)

const (
	RecoveryManifestProfile  = "yukh-security-audit-recovery-manifest/v1"
	MaxRecoveryManifestBytes = 1 << 20
	MaxRecoveryEpochFloors   = 100_000
)

type BackupEvidence struct {
	BackupID   string
	DatabaseID string
	Digest     Hash
	CapturedAt time.Time
}

type RecoveryManifest struct {
	ManifestID            string
	IdentityBackup        BackupEvidence
	AuditBackup           BackupEvidence
	AuditBackupTreeHead   TreeHead
	CheckpointReference   string
	CheckpointTreeHead    TreeHead
	CheckpointConsistency ConsistencyProof
	IdentityEpochFloors   []identity.EpochFloor
	IdentityWallHighWater time.Time
	CreatedAt             time.Time
	Algorithm             string
	KeyID                 string
}

type SignedRecoveryManifest struct {
	Manifest  RecoveryManifest
	Canonical []byte
	Signature []byte
	Reference string
}

type RecoveryManifestInput struct {
	ManifestID            string
	IdentityBackup        BackupEvidence
	AuditBackup           BackupEvidence
	AuditBackupTreeSize   uint64
	CheckpointReference   string
	IdentityEpochFloors   []identity.EpochFloor
	IdentityWallHighWater time.Time
	CreatedAt             time.Time
}

type RecoverySigningSelection struct{ KeyID, Algorithm string }

type RecoverySigner interface {
	SelectRecovery(context.Context) (RecoverySigningSelection, error)
	SignRecovery(context.Context, RecoverySigningSelection, []byte) ([]byte, error)
}

type ReadinessPolicy struct {
	MaximumCheckpointAge   time.Duration
	ClockRollbackTolerance time.Duration
	RequireWitness         bool
	MaximumEntries         uint64
	MaximumDatabaseBytes   uint64
}

type SignerReadiness interface {
	CheckSigner(context.Context, CheckpointSigningSelection) error
}

func KeyTrustedAt(statement VerificationKeyStatement, at time.Time) bool {
	return validMillis(at) && keyTrustedAt(statement, at)
}

type canonicalBackupEvidence struct {
	BackupID   string `json:"backup_id"`
	DatabaseID string `json:"database_id"`
	Digest     string `json:"digest"`
	CapturedAt string `json:"captured_at"`
}

type canonicalEpochFloor struct {
	TenantID    string `json:"tenant_id"`
	PrincipalID string `json:"principal_id"`
	Epoch       uint64 `json:"epoch"`
}

type canonicalRecoveryManifest struct {
	Profile               string                  `json:"profile"`
	ManifestID            string                  `json:"manifest_id"`
	IdentityBackup        canonicalBackupEvidence `json:"identity_backup"`
	AuditBackup           canonicalBackupEvidence `json:"audit_backup"`
	AuditBackupTreeSize   uint64                  `json:"audit_backup_tree_size"`
	AuditBackupRootHash   string                  `json:"audit_backup_root_hash"`
	CheckpointReference   string                  `json:"checkpoint_reference"`
	CheckpointTreeSize    uint64                  `json:"checkpoint_tree_size"`
	CheckpointRootHash    string                  `json:"checkpoint_root_hash"`
	ConsistencyProof      []string                `json:"consistency_proof"`
	IdentityEpochFloors   []canonicalEpochFloor   `json:"identity_epoch_floors"`
	IdentityWallHighWater string                  `json:"identity_wall_high_water"`
	CreatedAt             string                  `json:"created_at"`
	Algorithm             string                  `json:"algorithm"`
	KeyID                 string                  `json:"key_id"`
}

func CanonicalRecoveryManifest(value RecoveryManifest) ([]byte, error) {
	if !validRecoveryManifest(value) {
		return nil, ErrUnavailable
	}
	floors := make([]canonicalEpochFloor, len(value.IdentityEpochFloors))
	for index, floor := range value.IdentityEpochFloors {
		floors[index] = canonicalEpochFloor{TenantID: floor.TenantID, PrincipalID: floor.PrincipalID, Epoch: floor.Epoch}
	}
	proof := make([]string, len(value.CheckpointConsistency.Path))
	for index, hash := range value.CheckpointConsistency.Path {
		proof[index] = encodeDigest(hash)
	}
	canonical := canonicalRecoveryManifest{Profile: RecoveryManifestProfile, ManifestID: value.ManifestID,
		IdentityBackup: encodeBackup(value.IdentityBackup), AuditBackup: encodeBackup(value.AuditBackup),
		AuditBackupTreeSize: value.AuditBackupTreeHead.Size, AuditBackupRootHash: encodeDigest(value.AuditBackupTreeHead.Root),
		CheckpointReference: value.CheckpointReference, CheckpointTreeSize: value.CheckpointTreeHead.Size, CheckpointRootHash: encodeDigest(value.CheckpointTreeHead.Root),
		ConsistencyProof: proof, IdentityEpochFloors: floors, IdentityWallHighWater: formatMillis(value.IdentityWallHighWater), CreatedAt: formatMillis(value.CreatedAt), Algorithm: value.Algorithm, KeyID: value.KeyID}
	return canonicalJSON(canonical, MaxRecoveryManifestBytes)
}

func ParseCanonicalRecoveryManifest(raw []byte) (RecoveryManifest, error) {
	var value canonicalRecoveryManifest
	if !decodeCanonical(raw, MaxRecoveryManifestBytes, &value) || value.Profile != RecoveryManifestProfile {
		return RecoveryManifest{}, ErrUnavailable
	}
	identityBackup, ok := decodeBackup(value.IdentityBackup)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	auditBackup, ok := decodeBackup(value.AuditBackup)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	auditRoot, ok := decodeHash(value.AuditBackupRootHash)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	checkpointRoot, ok := decodeHash(value.CheckpointRootHash)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	created, ok := parseMillis(value.CreatedAt)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	identityHighWater, ok := parseMillis(value.IdentityWallHighWater)
	if !ok {
		return RecoveryManifest{}, ErrUnavailable
	}
	proof := make([]Hash, len(value.ConsistencyProof))
	for index, encoded := range value.ConsistencyProof {
		hash, ok := decodeHash(encoded)
		if !ok {
			return RecoveryManifest{}, ErrUnavailable
		}
		proof[index] = hash
	}
	floors := make([]identity.EpochFloor, len(value.IdentityEpochFloors))
	for index, floor := range value.IdentityEpochFloors {
		floors[index] = identity.EpochFloor{TenantID: floor.TenantID, PrincipalID: floor.PrincipalID, Epoch: floor.Epoch}
	}
	result := RecoveryManifest{ManifestID: value.ManifestID, IdentityBackup: identityBackup, AuditBackup: auditBackup,
		AuditBackupTreeHead: TreeHead{Size: value.AuditBackupTreeSize, Root: auditRoot}, CheckpointReference: value.CheckpointReference,
		CheckpointTreeHead:    TreeHead{Size: value.CheckpointTreeSize, Root: checkpointRoot},
		CheckpointConsistency: ConsistencyProof{FirstSize: value.AuditBackupTreeSize, SecondSize: value.CheckpointTreeSize, Path: proof},
		IdentityEpochFloors:   floors, IdentityWallHighWater: identityHighWater, CreatedAt: created, Algorithm: value.Algorithm, KeyID: value.KeyID}
	if !validRecoveryManifest(result) {
		return RecoveryManifest{}, ErrUnavailable
	}
	reencoded, err := CanonicalRecoveryManifest(result)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return RecoveryManifest{}, ErrUnavailable
	}
	return result, nil
}

func RecoveryManifestPreimage(canonical []byte) ([]byte, error) {
	if _, err := ParseCanonicalRecoveryManifest(canonical); err != nil {
		return nil, ErrUnavailable
	}
	return append([]byte("yukh-coordination:audit-recovery-manifest:v1\n"), canonical...), nil
}

func RecoveryManifestReference(canonical, signature []byte) (string, error) {
	if _, err := ParseCanonicalRecoveryManifest(canonical); err != nil || len(signature) != ed25519.SignatureSize {
		return "", ErrUnavailable
	}
	preimage := append([]byte("yukh-coordination:audit-recovery-reference:v1\n"), canonical...)
	preimage = append(preimage, signature...)
	digest := sha256.Sum256(preimage)
	return "audit-recovery:" + encodeDigest(digest), nil
}

func VerifySignedRecoveryManifest(signed SignedRecoveryManifest, statement VerificationKeyStatement, checkpoint SignedCheckpoint, checkpointStatement VerificationKeyStatement) error {
	manifest, err := ParseCanonicalRecoveryManifest(signed.Canonical)
	if err != nil || !sameRecoveryManifest(manifest, signed.Manifest) || manifest.KeyID != statement.KeyID || manifest.Algorithm != CheckpointAlgorithm {
		return ErrUnavailable
	}
	preimage, _ := RecoveryManifestPreimage(signed.Canonical)
	if !ed25519.Verify(statement.PublicKey, preimage, signed.Signature) {
		return ErrUnavailable
	}
	reference, err := RecoveryManifestReference(signed.Canonical, signed.Signature)
	if err != nil || (signed.Reference != "" && signed.Reference != reference) {
		return ErrUnavailable
	}
	if !keyTrustedAt(statement, manifest.CreatedAt) {
		return ErrUnavailable
	}
	trust, err := VerifySignedCheckpoint(checkpoint, checkpointStatement)
	if err != nil || trust != CheckpointTrusted || checkpoint.Reference != manifest.CheckpointReference || checkpoint.Checkpoint.TreeSize != manifest.CheckpointTreeHead.Size || checkpoint.Checkpoint.RootHash != manifest.CheckpointTreeHead.Root {
		return ErrUnavailable
	}
	if !VerifyConsistency(manifest.AuditBackupTreeHead.Root, manifest.CheckpointTreeHead.Root, manifest.CheckpointConsistency) {
		return ErrUnavailable
	}
	return nil
}

func DigestBackupFile(path string) (Hash, error) {
	file, err := os.Open(path)
	if err != nil {
		return Hash{}, ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	linked, linkErr := os.Lstat(path)
	if err != nil || linkErr != nil || !opened.Mode().IsRegular() || !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) {
		return Hash{}, ErrUnavailable
	}
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if readErr != nil {
			if readErr != io.EOF {
				return Hash{}, ErrUnavailable
			}
			break
		}
	}
	var result Hash
	copy(result[:], hash.Sum(nil))
	return result, nil
}

func encodeBackup(value BackupEvidence) canonicalBackupEvidence {
	return canonicalBackupEvidence{BackupID: value.BackupID, DatabaseID: value.DatabaseID, Digest: encodeDigest(value.Digest), CapturedAt: formatMillis(value.CapturedAt)}
}
func decodeBackup(value canonicalBackupEvidence) (BackupEvidence, bool) {
	digest, ok := decodeHash(value.Digest)
	if !ok {
		return BackupEvidence{}, false
	}
	captured, ok := parseMillis(value.CapturedAt)
	return BackupEvidence{BackupID: value.BackupID, DatabaseID: value.DatabaseID, Digest: digest, CapturedAt: captured}, ok
}

func validRecoveryManifest(value RecoveryManifest) bool {
	if _, err := canonicalV7(value.ManifestID); err != nil {
		return false
	}
	if !validBackup(value.IdentityBackup) || !validBackup(value.AuditBackup) || value.IdentityBackup.CapturedAt.After(value.CreatedAt) || value.AuditBackup.CapturedAt.After(value.CreatedAt) || !validMillis(value.IdentityWallHighWater) || value.IdentityWallHighWater.After(value.IdentityBackup.CapturedAt) || !validMillis(value.CreatedAt) || value.Algorithm != CheckpointAlgorithm || !keyIDPattern.MatchString(value.KeyID) || !validCheckpointReference(value.CheckpointReference) {
		return false
	}
	if value.AuditBackupTreeHead.Size == 0 || value.AuditBackupTreeHead.Size > value.CheckpointTreeHead.Size || value.CheckpointTreeHead.Size > MaxJSONSafeSequence || value.CheckpointConsistency.FirstSize != value.AuditBackupTreeHead.Size || value.CheckpointConsistency.SecondSize != value.CheckpointTreeHead.Size || len(value.CheckpointConsistency.Path) > MaxProofNodes {
		return false
	}
	if len(value.IdentityEpochFloors) > MaxRecoveryEpochFloors {
		return false
	}
	previous := ""
	for _, floor := range value.IdentityEpochFloors {
		key := floor.TenantID + "\x00" + floor.PrincipalID
		if !tenantPattern.MatchString(floor.TenantID) || !validDigestText(floor.PrincipalID) || floor.Epoch == 0 || floor.Epoch > MaxJSONSafeSequence || key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func validBackup(value BackupEvidence) bool {
	_, first := canonicalV7(value.BackupID)
	_, second := canonicalV7(value.DatabaseID)
	return first == nil && second == nil && validMillis(value.CapturedAt)
}
func keyTrustedAt(statement VerificationKeyStatement, at time.Time) bool {
	return !at.Before(statement.ActiveFrom) && (statement.RetiredAt == nil || at.Before(*statement.RetiredAt)) && !(statement.CompromisedFrom != nil && !at.Before(*statement.CompromisedFrom) && (statement.CompromisedUntil == nil || at.Before(*statement.CompromisedUntil)))
}
func sameRecoveryManifest(left, right RecoveryManifest) bool {
	a, errA := CanonicalRecoveryManifest(left)
	b, errB := CanonicalRecoveryManifest(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}
