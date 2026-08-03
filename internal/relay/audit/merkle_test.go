package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

type merkleVector struct {
	Profile      string   `json:"profile"`
	ChainDigests []string `json:"chain_digests"`
	LeafHashes   []string `json:"leaf_hashes"`
	TreeHeads    []struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
	} `json:"tree_heads"`
	InclusionProofs []struct {
		LeafIndex uint64   `json:"leaf_index"`
		TreeSize  uint64   `json:"tree_size"`
		Path      []string `json:"path"`
	} `json:"inclusion_proofs"`
	ConsistencyProofs []struct {
		FirstSize  uint64   `json:"first_size"`
		SecondSize uint64   `json:"second_size"`
		Path       []string `json:"path"`
	} `json:"consistency_proofs"`
}

func TestIndependentMerkleVector(t *testing.T) {
	var vector merkleVector
	if err := json.Unmarshal(readFixture(t, "audit-merkle.canonical.json"), &vector); err != nil || vector.Profile != "yukh-security-audit-merkle/v1" || len(vector.ChainDigests) != 7 || len(vector.LeafHashes) != 7 {
		t.Fatalf("invalid vector: %#v, %v", vector, err)
	}
	leaves := make([]Hash, len(vector.ChainDigests))
	for index, encoded := range vector.ChainDigests {
		chain := decodeVectorHash(t, encoded)
		leaf, err := MerkleLeafHash(uint64(index+1), chain)
		if err != nil || leaf != Hash(decodeVectorHash(t, vector.LeafHashes[index])) {
			t.Fatalf("leaf %d mismatch: %v", index, err)
		}
		leaves[index] = leaf
	}
	for _, head := range vector.TreeHeads {
		if got := MerkleRoot(leaves[:head.TreeSize]); got != Hash(decodeVectorHash(t, head.RootHash)) {
			t.Fatalf("root %d mismatch", head.TreeSize)
		}
	}
	root := MerkleRoot(leaves)
	for _, item := range vector.InclusionProofs {
		proof := InclusionProof{LeafIndex: item.LeafIndex, TreeSize: item.TreeSize, Path: decodeVectorPath(t, item.Path)}
		generated, err := BuildInclusionProof(leaves[:item.TreeSize], item.LeafIndex)
		if err != nil || !equalHashPaths(generated.Path, proof.Path) || !VerifyInclusion(leaves[item.LeafIndex], root, proof) {
			t.Fatalf("inclusion vector index=%d: %v", item.LeafIndex, err)
		}
	}
	for _, item := range vector.ConsistencyProofs {
		proof := ConsistencyProof{FirstSize: item.FirstSize, SecondSize: item.SecondSize, Path: decodeVectorPath(t, item.Path)}
		generated, err := BuildConsistencyProof(leaves[:item.SecondSize], item.FirstSize)
		if err != nil || !equalHashPaths(generated.Path, proof.Path) || !VerifyConsistency(MerkleRoot(leaves[:item.FirstSize]), root, proof) {
			t.Fatalf("consistency vector %d->%d: %v", item.FirstSize, item.SecondSize, err)
		}
	}
}

func TestMerkleProofsAcrossTreeShapes(t *testing.T) {
	leaves := merkleFixtureLeaves(t, 19)
	for size := 1; size <= len(leaves); size++ {
		root := MerkleRoot(leaves[:size])
		for index := 0; index < size; index++ {
			proof, err := BuildInclusionProof(leaves[:size], uint64(index))
			if err != nil || !VerifyInclusion(leaves[index], root, proof) {
				t.Fatalf("inclusion size=%d index=%d: %v", size, index, err)
			}
			if len(proof.Path) > 0 {
				damaged := proof
				damaged.Path = append([]Hash(nil), proof.Path...)
				damaged.Path[0][0] ^= 1
				if VerifyInclusion(leaves[index], root, damaged) {
					t.Fatalf("damaged inclusion accepted size=%d index=%d", size, index)
				}
			}
		}
		for first := 0; first <= size; first++ {
			proof, err := BuildConsistencyProof(leaves[:size], uint64(first))
			if err != nil || !VerifyConsistency(MerkleRoot(leaves[:first]), root, proof) {
				t.Fatalf("consistency %d->%d: %v path=%d", first, size, err, len(proof.Path))
			}
			if len(proof.Path) > 0 {
				damaged := proof
				damaged.Path = append([]Hash(nil), proof.Path...)
				damaged.Path[len(damaged.Path)-1][0] ^= 1
				if VerifyConsistency(MerkleRoot(leaves[:first]), root, damaged) {
					t.Fatalf("damaged consistency accepted %d->%d", first, size)
				}
			}
		}
	}
}

func TestMerkleProofBoundsAndWrongHeadsFail(t *testing.T) {
	leaves := merkleFixtureLeaves(t, 7)
	if _, err := BuildInclusionProof(nil, 0); err == nil {
		t.Fatal("empty inclusion request accepted")
	}
	if _, err := BuildInclusionProof(leaves, 7); err == nil {
		t.Fatal("out-of-range inclusion request accepted")
	}
	if _, err := BuildConsistencyProof(leaves, 8); err == nil {
		t.Fatal("reversed consistency request accepted")
	}
	proof, err := BuildInclusionProof(leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	wrong := MerkleRoot(leaves)
	wrong[0] ^= 1
	if VerifyInclusion(leaves[3], wrong, proof) {
		t.Fatal("wrong inclusion root accepted")
	}
	truncated := proof
	truncated.Path = append([]Hash(nil), proof.Path[:len(proof.Path)-1]...)
	if VerifyInclusion(leaves[3], MerkleRoot(leaves), truncated) {
		t.Fatal("truncated inclusion path accepted")
	}
	extended := proof
	extended.Path = append(append([]Hash(nil), proof.Path...), Hash{})
	if VerifyInclusion(leaves[3], MerkleRoot(leaves), extended) {
		t.Fatal("extended inclusion path accepted")
	}
	consistency, err := BuildConsistencyProof(leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyConsistency(MerkleRoot(leaves[:3]), wrong, consistency) {
		t.Fatal("wrong consistency root accepted")
	}
	truncatedConsistency := consistency
	truncatedConsistency.Path = append([]Hash(nil), consistency.Path[:len(consistency.Path)-1]...)
	if VerifyConsistency(MerkleRoot(leaves[:3]), MerkleRoot(leaves), truncatedConsistency) {
		t.Fatal("truncated consistency path accepted")
	}
	extendedConsistency := consistency
	extendedConsistency.Path = append(append([]Hash(nil), consistency.Path...), Hash{})
	if VerifyConsistency(MerkleRoot(leaves[:3]), MerkleRoot(leaves), extendedConsistency) {
		t.Fatal("extended consistency path accepted")
	}
}

func merkleFixtureLeaves(t *testing.T, count int) []Hash {
	t.Helper()
	leaves := make([]Hash, count)
	for i := range leaves {
		chain := sha256.Sum256([]byte{byte(i)})
		leaf, err := MerkleLeafHash(uint64(i+1), chain)
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = leaf
	}
	return leaves
}

func decodeVectorHash(t *testing.T, value string) [sha256.Size]byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		t.Fatalf("invalid vector hash %q: %v", value, err)
	}
	var result [sha256.Size]byte
	copy(result[:], raw)
	return result
}

func decodeVectorPath(t *testing.T, values []string) []Hash {
	t.Helper()
	result := make([]Hash, len(values))
	for index, value := range values {
		result[index] = Hash(decodeVectorHash(t, value))
	}
	return result
}

func equalHashPaths(left, right []Hash) bool {
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
