package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

const MaxProofNodes = 54

type Hash [sha256.Size]byte

type TreeHead struct {
	Size uint64
	Root Hash
}

type InclusionProof struct {
	LeafIndex uint64
	TreeSize  uint64
	Path      []Hash
}

type ConsistencyProof struct {
	FirstSize  uint64
	SecondSize uint64
	Path       []Hash
}

func EmptyMerkleRoot() Hash { return sha256.Sum256(nil) }

func MerkleLeafHash(sequence uint64, chainDigest [sha256.Size]byte) (Hash, error) {
	if sequence == 0 || sequence > MaxJSONSafeSequence {
		return Hash{}, ErrUnavailable
	}
	preimage := make([]byte, 1, 1+48+8+sha256.Size)
	preimage[0] = 0
	preimage = append(preimage, "yukh-coordination:audit-merkle-leaf:v1\n"...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	preimage = append(preimage, encoded[:]...)
	preimage = append(preimage, chainDigest[:]...)
	return sha256.Sum256(preimage), nil
}

func MerkleNodeHash(left, right Hash) Hash {
	preimage := make([]byte, 1, 1+2*sha256.Size)
	preimage[0] = 1
	preimage = append(preimage, left[:]...)
	preimage = append(preimage, right[:]...)
	return sha256.Sum256(preimage)
}

// MerkleRoot computes RFC 9162 MTH from already domain-separated leaf hashes.
func MerkleRoot(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyMerkleRoot()
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := largestPowerLessThan(uint64(len(leaves)))
	return MerkleNodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

func BuildInclusionProof(leaves []Hash, leafIndex uint64) (InclusionProof, error) {
	if len(leaves) == 0 || uint64(len(leaves)) > MaxJSONSafeSequence || leafIndex >= uint64(len(leaves)) {
		return InclusionProof{}, ErrUnavailable
	}
	path := make([]Hash, 0, bits.Len64(uint64(len(leaves))))
	buildInclusionPath(leaves, leafIndex, &path)
	return InclusionProof{LeafIndex: leafIndex, TreeSize: uint64(len(leaves)), Path: path}, nil
}

func VerifyInclusion(leaf Hash, root Hash, proof InclusionProof) bool {
	if proof.TreeSize == 0 || proof.TreeSize > MaxJSONSafeSequence || proof.LeafIndex >= proof.TreeSize || len(proof.Path) > MaxProofNodes {
		return false
	}
	fn, sn, result := proof.LeafIndex, proof.TreeSize-1, leaf
	for _, sibling := range proof.Path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			result = MerkleNodeHash(sibling, result)
			if fn&1 == 0 {
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			result = MerkleNodeHash(result, sibling)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && result == root
}

func BuildConsistencyProof(leaves []Hash, firstSize uint64) (ConsistencyProof, error) {
	secondSize := uint64(len(leaves))
	if secondSize > MaxJSONSafeSequence || firstSize > secondSize {
		return ConsistencyProof{}, ErrUnavailable
	}
	proof := ConsistencyProof{FirstSize: firstSize, SecondSize: secondSize}
	if firstSize == 0 || firstSize == secondSize {
		return proof, nil
	}
	path := make([]Hash, 0, bits.Len64(secondSize)+1)
	buildConsistencyPath(leaves, firstSize, true, &path)
	proof.Path = path
	return proof, nil
}

func VerifyConsistency(firstRoot, secondRoot Hash, proof ConsistencyProof) bool {
	if proof.FirstSize > proof.SecondSize || proof.SecondSize > MaxJSONSafeSequence || len(proof.Path) > MaxProofNodes {
		return false
	}
	if proof.FirstSize == 0 {
		return len(proof.Path) == 0 && firstRoot == EmptyMerkleRoot()
	}
	if proof.FirstSize == proof.SecondSize {
		return len(proof.Path) == 0 && firstRoot == secondRoot
	}
	if len(proof.Path) == 0 {
		return false
	}
	path := proof.Path
	if proof.FirstSize&(proof.FirstSize-1) == 0 {
		path = make([]Hash, 0, len(proof.Path)+1)
		path = append(path, firstRoot)
		path = append(path, proof.Path...)
	}
	fn, sn := proof.FirstSize-1, proof.SecondSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	first, second := path[0], path[0]
	for _, node := range path[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			first = MerkleNodeHash(node, first)
			second = MerkleNodeHash(node, second)
			if fn&1 == 0 {
				for fn != 0 && fn&1 == 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			second = MerkleNodeHash(second, node)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && first == firstRoot && second == secondRoot
}

func buildInclusionPath(leaves []Hash, index uint64, path *[]Hash) {
	if len(leaves) == 1 {
		return
	}
	k := largestPowerLessThan(uint64(len(leaves)))
	if index < k {
		buildInclusionPath(leaves[:k], index, path)
		*path = append(*path, MerkleRoot(leaves[k:]))
		return
	}
	buildInclusionPath(leaves[k:], index-k, path)
	*path = append(*path, MerkleRoot(leaves[:k]))
}

func buildConsistencyPath(leaves []Hash, firstSize uint64, complete bool, path *[]Hash) {
	if firstSize == uint64(len(leaves)) {
		if !complete {
			*path = append(*path, MerkleRoot(leaves))
		}
		return
	}
	k := largestPowerLessThan(uint64(len(leaves)))
	if firstSize <= k {
		buildConsistencyPath(leaves[:k], firstSize, complete, path)
		*path = append(*path, MerkleRoot(leaves[k:]))
		return
	}
	buildConsistencyPath(leaves[k:], firstSize-k, false, path)
	*path = append(*path, MerkleRoot(leaves[:k]))
}

func largestPowerLessThan(value uint64) uint64 {
	return uint64(1) << (bits.Len64(value-1) - 1)
}
