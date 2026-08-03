package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"math/bits"
	"sort"

	"github.com/nomed/yukh-coordination/internal/relay/audit"
)

type nodeCoordinate struct {
	level uint64
	index uint64
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type nodeWriter interface {
	rowQuerier
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// RebuildMerkleDatabase is the narrow recovery entrypoint for a derivable
// Merkle-cache failure. It never bypasses canonical entry and chain checks.
func RebuildMerkleDatabase(ctx context.Context, path string) error {
	if ctx == nil {
		return audit.ErrUnavailable
	}
	ledger, err := open(path, false)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer ledger.Close()
	return ledger.RebuildMerkle(ctx)
}

// RebuildMerkle verifies the authoritative chain first, then replaces only the
// derivable Merkle cache and unsigned local root in one transaction.
func (l *Ledger) RebuildMerkle(ctx context.Context) error {
	if l == nil || l.db == nil || ctx == nil {
		return audit.ErrUnavailable
	}
	tx, err := beginImmediate(ctx, l.db)
	if err != nil {
		return audit.ErrUnavailable
	}
	defer tx.rollback()
	size, expected, err := verifiedChainState(ctx, tx.conn)
	if err != nil {
		return audit.ErrUnavailable
	}
	for _, statement := range []string{"DROP TRIGGER IF EXISTS merkle_nodes_no_update", "DROP TRIGGER IF EXISTS merkle_nodes_no_delete", "DROP TRIGGER IF EXISTS audit_metadata_append_only", "DELETE FROM merkle_nodes"} {
		if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	coordinates := make([]nodeCoordinate, 0, len(expected))
	for coordinate := range expected {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(i, j int) bool {
		if coordinates[i].level == coordinates[j].level {
			return coordinates[i].index < coordinates[j].index
		}
		return coordinates[i].level < coordinates[j].level
	})
	for _, coordinate := range coordinates {
		if err := insertNode(ctx, tx.conn, coordinate.level, coordinate.index, expected[coordinate]); err != nil {
			return audit.ErrUnavailable
		}
	}
	root := rootFromExpected(expected, size)
	if _, err := tx.conn.ExecContext(ctx, "UPDATE audit_metadata SET merkle_size = ?, merkle_root = ? WHERE singleton = 1", size, root[:]); err != nil {
		return audit.ErrUnavailable
	}
	for _, statement := range []string{merkleNodesNoUpdateTrigger, merkleNodesNoDeleteTrigger, metadataAppendTriggerV2} {
		if _, err := tx.conn.ExecContext(ctx, statement); err != nil {
			return audit.ErrUnavailable
		}
	}
	if err := tx.commit(ctx); err != nil {
		return audit.ErrUnavailable
	}
	return l.Verify(ctx)
}

func (l *Ledger) MerkleTreeHead(ctx context.Context, treeSize uint64) (audit.TreeHead, error) {
	if l == nil || l.db == nil || ctx == nil || treeSize > audit.MaxJSONSafeSequence {
		return audit.TreeHead{}, audit.ErrUnavailable
	}
	var available uint64
	if err := l.db.QueryRowContext(ctx, "SELECT merkle_size FROM audit_metadata WHERE singleton = 1").Scan(&available); err != nil || treeSize > available {
		return audit.TreeHead{}, audit.ErrUnavailable
	}
	root, err := subtreeHash(ctx, l.db, 0, treeSize)
	if err != nil {
		return audit.TreeHead{}, audit.ErrUnavailable
	}
	return audit.TreeHead{Size: treeSize, Root: root}, nil
}

func (l *Ledger) MerkleInclusionProof(ctx context.Context, leafIndex, treeSize uint64) (audit.InclusionProof, error) {
	if l == nil || l.db == nil || ctx == nil || treeSize == 0 || treeSize > audit.MaxJSONSafeSequence || leafIndex >= treeSize {
		return audit.InclusionProof{}, audit.ErrUnavailable
	}
	var available uint64
	if err := l.db.QueryRowContext(ctx, "SELECT merkle_size FROM audit_metadata WHERE singleton = 1").Scan(&available); err != nil || treeSize > available {
		return audit.InclusionProof{}, audit.ErrUnavailable
	}
	path := make([]audit.Hash, 0, bits.Len64(treeSize))
	if err := inclusionPath(ctx, l.db, 0, treeSize, leafIndex, &path); err != nil || len(path) > audit.MaxProofNodes {
		return audit.InclusionProof{}, audit.ErrUnavailable
	}
	return audit.InclusionProof{LeafIndex: leafIndex, TreeSize: treeSize, Path: path}, nil
}

func (l *Ledger) MerkleConsistencyProof(ctx context.Context, firstSize, secondSize uint64) (audit.ConsistencyProof, error) {
	if l == nil || l.db == nil || ctx == nil || firstSize > secondSize || secondSize > audit.MaxJSONSafeSequence {
		return audit.ConsistencyProof{}, audit.ErrUnavailable
	}
	var available uint64
	if err := l.db.QueryRowContext(ctx, "SELECT merkle_size FROM audit_metadata WHERE singleton = 1").Scan(&available); err != nil || secondSize > available {
		return audit.ConsistencyProof{}, audit.ErrUnavailable
	}
	proof := audit.ConsistencyProof{FirstSize: firstSize, SecondSize: secondSize}
	if firstSize == 0 || firstSize == secondSize {
		return proof, nil
	}
	path := make([]audit.Hash, 0, bits.Len64(secondSize)+1)
	if err := consistencyPath(ctx, l.db, 0, secondSize, firstSize, true, &path); err != nil || len(path) > audit.MaxProofNodes {
		return audit.ConsistencyProof{}, audit.ErrUnavailable
	}
	proof.Path = path
	return proof, nil
}

func (l *Ledger) MerkleLeaf(ctx context.Context, leafIndex uint64) (audit.Hash, error) {
	if l == nil || l.db == nil || ctx == nil || leafIndex >= audit.MaxJSONSafeSequence {
		return audit.Hash{}, audit.ErrUnavailable
	}
	var chainBytes []byte
	if err := l.db.QueryRowContext(ctx, "SELECT chain_digest FROM audit_entries WHERE sequence = ?", leafIndex+1).Scan(&chainBytes); err != nil || len(chainBytes) != sha256.Size {
		return audit.Hash{}, audit.ErrUnavailable
	}
	var chainDigest [sha256.Size]byte
	copy(chainDigest[:], chainBytes)
	leaf, err := audit.MerkleLeafHash(leafIndex+1, chainDigest)
	if err != nil {
		return audit.Hash{}, audit.ErrUnavailable
	}
	return leaf, nil
}

func insertMerkleLeaf(ctx context.Context, query nodeWriter, leafIndex uint64, leaf audit.Hash) error {
	level, index, current := uint64(0), leafIndex, leaf
	if err := insertNode(ctx, query, level, index, current); err != nil {
		return err
	}
	for index&1 == 1 {
		left, err := readNode(ctx, query, level, index-1)
		if err != nil {
			return err
		}
		current = audit.MerkleNodeHash(left, current)
		index >>= 1
		level++
		if err := insertNode(ctx, query, level, index, current); err != nil {
			return err
		}
	}
	return nil
}

func insertNode(ctx context.Context, query nodeWriter, level, index uint64, hash audit.Hash) error {
	if level > 52 || index > audit.MaxJSONSafeSequence {
		return audit.ErrUnavailable
	}
	if _, err := query.ExecContext(ctx, "INSERT INTO merkle_nodes (level, node_index, node_hash) VALUES (?, ?, ?)", level, index, hash[:]); err != nil {
		return audit.ErrUnavailable
	}
	return nil
}

func readNode(ctx context.Context, query rowQuerier, level, index uint64) (audit.Hash, error) {
	var raw []byte
	if err := query.QueryRowContext(ctx, "SELECT node_hash FROM merkle_nodes WHERE level = ? AND node_index = ?", level, index).Scan(&raw); err != nil || len(raw) != sha256.Size {
		return audit.Hash{}, audit.ErrUnavailable
	}
	var result audit.Hash
	copy(result[:], raw)
	return result, nil
}

func subtreeHash(ctx context.Context, query rowQuerier, start, size uint64) (audit.Hash, error) {
	if size == 0 {
		return audit.EmptyMerkleRoot(), nil
	}
	if start > audit.MaxJSONSafeSequence || size > audit.MaxJSONSafeSequence || start > audit.MaxJSONSafeSequence-size {
		return audit.Hash{}, audit.ErrUnavailable
	}
	if size&(size-1) == 0 && start%size == 0 {
		return readNode(ctx, query, uint64(bits.TrailingZeros64(size)), start/size)
	}
	k := largestPowerLessThan(size)
	left, err := subtreeHash(ctx, query, start, k)
	if err != nil {
		return audit.Hash{}, err
	}
	right, err := subtreeHash(ctx, query, start+k, size-k)
	if err != nil {
		return audit.Hash{}, err
	}
	return audit.MerkleNodeHash(left, right), nil
}

func inclusionPath(ctx context.Context, query rowQuerier, start, size, index uint64, path *[]audit.Hash) error {
	if size == 1 {
		return nil
	}
	k := largestPowerLessThan(size)
	if index < k {
		if err := inclusionPath(ctx, query, start, k, index, path); err != nil {
			return err
		}
		sibling, err := subtreeHash(ctx, query, start+k, size-k)
		if err != nil {
			return err
		}
		*path = append(*path, sibling)
		return nil
	}
	if err := inclusionPath(ctx, query, start+k, size-k, index-k, path); err != nil {
		return err
	}
	sibling, err := subtreeHash(ctx, query, start, k)
	if err != nil {
		return err
	}
	*path = append(*path, sibling)
	return nil
}

func consistencyPath(ctx context.Context, query rowQuerier, start, size, firstSize uint64, complete bool, path *[]audit.Hash) error {
	if firstSize == size {
		if !complete {
			hash, err := subtreeHash(ctx, query, start, size)
			if err != nil {
				return err
			}
			*path = append(*path, hash)
		}
		return nil
	}
	k := largestPowerLessThan(size)
	if firstSize <= k {
		if err := consistencyPath(ctx, query, start, k, firstSize, complete, path); err != nil {
			return err
		}
		hash, err := subtreeHash(ctx, query, start+k, size-k)
		if err != nil {
			return err
		}
		*path = append(*path, hash)
		return nil
	}
	if err := consistencyPath(ctx, query, start+k, size-k, firstSize-k, false, path); err != nil {
		return err
	}
	hash, err := subtreeHash(ctx, query, start, k)
	if err != nil {
		return err
	}
	*path = append(*path, hash)
	return nil
}

func addExpectedLeaf(nodes map[nodeCoordinate]audit.Hash, leafIndex uint64, leaf audit.Hash) {
	coordinate := nodeCoordinate{level: 0, index: leafIndex}
	nodes[coordinate] = leaf
	current := leaf
	for coordinate.index&1 == 1 {
		left := nodes[nodeCoordinate{level: coordinate.level, index: coordinate.index - 1}]
		current = audit.MerkleNodeHash(left, current)
		coordinate.index >>= 1
		coordinate.level++
		nodes[coordinate] = current
	}
}

func rootFromExpected(nodes map[nodeCoordinate]audit.Hash, size uint64) audit.Hash {
	if size == 0 {
		return audit.EmptyMerkleRoot()
	}
	return expectedSubtree(nodes, 0, size)
}

func expectedSubtree(nodes map[nodeCoordinate]audit.Hash, start, size uint64) audit.Hash {
	if size&(size-1) == 0 && start%size == 0 {
		return nodes[nodeCoordinate{level: uint64(bits.TrailingZeros64(size)), index: start / size}]
	}
	k := largestPowerLessThan(size)
	return audit.MerkleNodeHash(expectedSubtree(nodes, start, k), expectedSubtree(nodes, start+k, size-k))
}

func verifyStoredNodes(ctx context.Context, db *sql.DB, expected map[nodeCoordinate]audit.Hash) error {
	rows, err := db.QueryContext(ctx, "SELECT level, node_index, node_hash FROM merkle_nodes ORDER BY level, node_index")
	if err != nil {
		return audit.ErrUnavailable
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var level, index uint64
		var raw []byte
		if err := rows.Scan(&level, &index, &raw); err != nil || len(raw) != sha256.Size {
			return audit.ErrUnavailable
		}
		want, exists := expected[nodeCoordinate{level: level, index: index}]
		if !exists || !bytes.Equal(raw, want[:]) {
			return audit.ErrUnavailable
		}
		seen++
	}
	if rows.Err() != nil || seen != len(expected) {
		return audit.ErrUnavailable
	}
	return nil
}

func largestPowerLessThan(value uint64) uint64 {
	return uint64(1) << (bits.Len64(value-1) - 1)
}
