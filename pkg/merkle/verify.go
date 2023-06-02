package merkle

import (
	"bytes"
	"fmt"
	"math/bits"

	"sigsum.org/sigsum-go/pkg/crypto"
)

func pathLength(index, size uint64) int {
	// k is the number of lowend bits that differ between fn and
	// sn, i.e., number of iterations until fn == sn.
	k := bits.Len64(index ^ (size - 1))
	return k + bits.OnesCount64(index>>k)
}

// VerifyConsistency verifies that a Merkle tree is consistent.  The algorithm
// used is in RFC 9162, §2.1.4.2.  It is the same proof technique as RFC 6962.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot *crypto.Hash, path []crypto.Hash) error {
	// First handle the easy cases where an empty proof is valid.
	if oldSize == newSize {
		// Consistent if and only if roots are equal.
		// Require empty path.
		if len(path) > 0 {
			return fmt.Errorf("non-empty consistency path for trees of equal size")
		}
		if *oldRoot != *newRoot {
			return fmt.Errorf("consistency check failed: same size, but roots differ")
		}
		return nil
	}
	if oldSize == 0 {
		// Anything is consistent with the empty tree.
		// Require empty path.
		if len(path) > 0 {
			return fmt.Errorf("non-empty consistency path for empty old tree")
		}
		if *oldRoot != HashEmptyTree() {
			return fmt.Errorf("unexpected root hash for the empty tree")
		}
		return nil
	}

	// The last leaf of the old tree is at index fn. Eliminate
	// bottom layers of the tree, until fn points at a subtree
	// that is a left child; that subtree is included as-is also
	// in the new tree, and that is the starting point for the
	// traversal.
	trimBits := bits.TrailingZeros64(oldSize) // Ones of oldSize - 1
	fn := (oldSize - 1) >> trimBits
	sn := (newSize - 1) >> trimBits

	wantLength := pathLength(fn, sn+1)
	if fn > 0 {
		wantLength++
	}
	if len(path) != wantLength {
		return fmt.Errorf("proof input is malformed: path length %d, should be %d", len(path), wantLength)
	}

	// If fn == 0, we start at the oldRoot, otherwise, the
	// starting point is the first element of the supplied path.
	var fr crypto.Hash
	if fn == 0 {
		fr = *oldRoot
	} else {
		fr, path = path[0], path[1:]
	}
	sr := fr

	for ; sn > 0; fn, sn = fn>>1, sn>>1 {
		if isOdd(fn) {
			// Node on path is left sibling
			fr = HashInteriorNode(&path[0], &fr)
			sr = HashInteriorNode(&path[0], &sr)
			path = path[1:]
		} else if fn < sn {
			// Node on path is right sibling for the larger tree.
			sr = HashInteriorNode(&sr, &path[0])
			path = path[1:]
		}
	}
	if len(path) > 0 {
		panic("internal error: left over path elements")
	}

	if !bytes.Equal(fr[:], oldRoot[:]) {
		return fmt.Errorf("invalid proof: old root mismatch")
	}
	if !bytes.Equal(sr[:], newRoot[:]) {
		return fmt.Errorf("invalid proof: new root mismatch")
	}
	return nil
}

func inclusionPathLength(index, size uint64) int {
	// k is the number of lowend bits that differ between fn and
	// sn, i.e., number of iterations until fn == sn.
	k := bits.Len64(index ^ (size - 1))
	return k + bits.OnesCount64(index>>k)
}

// VerifyInclusion verifies that something is in a Merkle tree. The
// algorithm used is equivalent to the one in in RFC 9162, §2.1.3.2.
// Note that with index == 0, size == 1, the empty path is considered
// a valid inclusion proof, and inclusion means that *leaf == *root.
func VerifyInclusion(leaf *crypto.Hash, index, size uint64, root *crypto.Hash, path []crypto.Hash) error {
	if index >= size {
		return fmt.Errorf("proof input is malformed: index out of range")
	}
	if got, want := len(path), inclusionPathLength(index, size); got != want {
		return fmt.Errorf("proof input is malformed: path length %d, should be %d", got, want)
	}

	if got, want := len(path), pathLength(index, size); got != want {
		return fmt.Errorf("proof input is malformed: path length %d, should be %d", got, want)
	}

	// Each iteration of the loop eliminates the bottom layer of
	// the tree. fn is the index in the tree for the hash of
	// interest, r. sn is the index of the last node in the
	// tree. All leaf nodes, in particular the final one with
	// index sn, are considered to be at the bottom layer, but
	// possibly with the parent located more than one layer above.
	// E.g., the tree with 3 leaves:
	//
	//     o      Root node
	//    / \
	//   o   \
	//  / \   \
	// o   o   o  The three leaf nodes
	// 0   1   2

	r := *leaf
	fn := index

	for sn := size - 1; sn > 0; fn, sn = fn>>1, sn>>1 {
		if isOdd(fn) {
			// Node on path is left sibling
			r = HashInteriorNode(&path[0], &r)
			path = path[1:]
		} else if fn < sn {
			// Node on path is right sibling
			r = HashInteriorNode(&r, &path[0])
			path = path[1:]
		}
	}
	if len(path) > 0 {
		panic("internal error: left over path elements")
	}
	if r != *root {
		return fmt.Errorf("invalid proof: root mismatch")
	}
	return nil
}

func extendRange(cr []crypto.Hash, i uint64, h crypto.Hash,
	makeNode func(left, right *crypto.Hash) crypto.Hash) []crypto.Hash {
	for s := i + 1; len(cr) > 0 && isEven(s); s >>= 1 {
		h = makeNode(&cr[len(cr)-1], &h)
		cr = cr[:len(cr)-1]
	}
	return append(cr, h)
}

// Returns the compact range of a leaf interval ending at 2^k, in
// reverse order, rightmost tree first.
func makeLeftRange(leaves []crypto.Hash) []crypto.Hash {
	if len(leaves) == 0 {
		return nil
	}
	cr := []crypto.Hash{leaves[len(leaves)-1]}
	for i := 1; i < len(leaves); i++ {
		cr = extendRange(cr, uint64(i), leaves[len(leaves)-1-i],
			func(left, right *crypto.Hash) crypto.Hash {
				return HashInteriorNode(right, left)
			})
	}
	return cr
}

// Returns the compact range of a leaf interval starting at 2^k.
func makeRightRange(leaves []crypto.Hash) []crypto.Hash {
	if len(leaves) == 0 {
		return nil
	}

	cr := []crypto.Hash{leaves[0]}
	for i := 1; i < len(leaves); i++ {
		cr = extendRange(cr, uint64(i), leaves[i], HashInteriorNode)
	}
	return cr
}

// VerifyBatchInclusion verifies a consecutive sequence of leaves are
// included in a Merkle tree. The algorithm is an extension of the
// inclusion proof in RFC 9162, §2.1.3.2, using inclusion proofs for
// the first and last (inclusive) leaves in the sequence.

// TODO: In case the leaf sequence extends all the way to the last
// leaf of the tree, the corresponding inclusion proof is redundant,
// so we should be able to do without it.

func VerifyInclusionBatch(leaves []crypto.Hash, fn, size uint64, root *crypto.Hash, startPath []crypto.Hash, endPath []crypto.Hash) error {
	if len(leaves) == 0 {
		return fmt.Errorf("range must be non-empty")
	}
	en := fn + uint64(len(leaves)) - 1
	if en >= size {
		return fmt.Errorf("end of range exceeds tree size")
	}

	if len(leaves) == 1 {
		if !pathEqual(startPath, endPath) {
			return fmt.Errorf("proof invalid, inconsistent paths")
		}
		return VerifyInclusion(&leaves[0], fn, size, root, startPath)
	}
	if len(startPath) != inclusionPathLength(fn, size) {
		return fmt.Errorf("proof invalid, wrong inclusion path length for first node")
	}
	if len(endPath) != inclusionPathLength(en, size) {
		return fmt.Errorf("proof invalid, wrong inclusion path length for last node")
	}
	// Find the bit index of the most significant bit where fn and en differ.
	k := bits.Len64(fn^en) - 1
	// Split the range at a multiple of 2^k, so that
	// split - 2^k <= fn < split <= en < split + 2^k
	split := en & -(uint64(1) << k)

	// Construct the compact range of the intermediate leaves,
	// i.e., excluding the leaves at fn and en, split as above.
	leftRange := makeLeftRange(leaves[1 : split-fn])
	rightRange := makeRightRange(leaves[split-fn : len(leaves)-1])

	fr := leaves[0]
	for i := 0; i < k; startPath, fn, i = startPath[1:], fn>>1, i+1 {
		if isOdd(fn) {
			// Node on path is left sibling
			fr = HashInteriorNode(&startPath[0], &fr)
		} else {
			// Node on path is right sibling, and must
			// match left compact range.
			s := &leftRange[len(leftRange)-1]
			leftRange = leftRange[:len(leftRange)-1]

			if *s != startPath[0] {
				return fmt.Errorf("unexpected path, inconsistent with leaf range")
			}
			fr = HashInteriorNode(&fr, s)
		}
	}

	// Process right path; left siblings for the first k levels
	// should match the compact range.
	sn := size - 1
	er := leaves[len(leaves)-1]

	for i := 0; i < k; en, sn, i = en>>1, sn>>1, i+1 {
		if isOdd(en) {
			// Node on path is left sibling, and must match right compact range.
			s := &rightRange[len(rightRange)-1]
			rightRange = rightRange[:len(rightRange)-1]

			if *s != endPath[0] {
				return fmt.Errorf("unexpected path, inconsistent with leaf range")
			}
			er = HashInteriorNode(s, &er)
			endPath = endPath[1:]
		} else if en < sn {
			// Node on path is right sibling.
			er = HashInteriorNode(&er, &endPath[0])
			endPath = endPath[1:]
		}
	}
	// Now we're just about to merge to a single node
	if isOdd(fn) || isEven(en) || fn+1 != en {
		panic(fmt.Sprintf("internal error expected adjacent fn, en, got %d, %d", fn, en))
	}
	if len(leftRange) > 0 || len(rightRange) > 0 {
		panic("internal error, left over compact range elements")
	}
	if startPath[0] != er || endPath[0] != fr {
		return fmt.Errorf("start and end trees not consistent")
	}
	if !pathEqual(startPath[1:], endPath[1:]) {
		return fmt.Errorf("proof invalid, inconsistent paths")
	}

	fr = HashInteriorNode(&fr, &er)
	return VerifyInclusion(&fr, fn>>1, (sn>>1)+1, root, startPath[1:])
}

func isOdd(num uint64) bool {
	return (num & 1) != 0
}

func isEven(num uint64) bool {
	return (num & 1) == 0
}

func pathEqual(a, b []crypto.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i, h := range a {
		if h != b[i] {
			return false
		}
	}
	return true
}
