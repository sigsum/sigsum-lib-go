package proof

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	SigsumProofVersion = 0
	ShortChecksumSize  = 2
)

type ShortChecksum [ShortChecksumSize]byte

// Variant of types.Leaf, with truncated checksum.
type ShortLeaf struct {
	ShortChecksum ShortChecksum
	Signature     crypto.Signature
	KeyHash       crypto.Hash
}

func NewShortLeaf(leaf *types.Leaf) ShortLeaf {
	proofLeaf := ShortLeaf{Signature: leaf.Signature, KeyHash: leaf.KeyHash}
	copy(proofLeaf.ShortChecksum[:], leaf.Checksum[:ShortChecksumSize])
	return proofLeaf
}

func (l *ShortLeaf) ToLeaf(checksum *crypto.Hash) (types.Leaf, error) {
	if !bytes.Equal(l.ShortChecksum[:], checksum[:ShortChecksumSize]) {
		return types.Leaf{}, fmt.Errorf("checksum doesn't match truncated checksum")
	}
	return types.Leaf{Checksum: *checksum, Signature: l.Signature, KeyHash: l.KeyHash}, nil
}

func (l *ShortLeaf) Parse(p ascii.Parser) error {
	// Same as a leaf line from get-leaves, except that checksum is truncated.
	v, err := p.GetValues("leaf", 3)
	if err != nil {
		return err
	}
	l.ShortChecksum, err = decodeShortChecksum(v[0])
	if err != nil {
		return fmt.Errorf("invalid submitter checksum: %v", err)
	}

	l.KeyHash, err = crypto.HashFromHex(v[1])
	if err != nil {
		return fmt.Errorf("invalid submitter key hash: %v", err)
	}
	l.Signature, err = crypto.SignatureFromHex(v[2])
	if err != nil {
		return fmt.Errorf("invalid leaf signature: %v", err)
	}
	return nil
}

func (l *ShortLeaf) ToASCII(w io.Writer) error {
	return ascii.WriteLine(w, "leaf", l.ShortChecksum[:], l.KeyHash[:], l.Signature[:])
}

type SigsumProof struct {
	LogKeyHash crypto.Hash
	Leaf       ShortLeaf
	TreeHead   types.CosignedTreeHead
	Inclusion  types.InclusionProof
}

func decodeShortChecksum(s string) (out ShortChecksum, err error) {
	var b []byte
	b, err = hex.DecodeString(s)
	if err != nil {
		return
	}
	if len(b) != len(out) {
		err = fmt.Errorf("unexpected checksum length, expected %d, got %d", len(out), len(b))
		return
	}
	copy(out[:], b)
	return
}

func (sp *SigsumProof) FromASCII(r io.Reader) error {
	// Could do something more fancy with a reader or scanner to
	// split on empty line, without reading all the data up front.
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	proofParts := bytes.Split(data, []byte{'\n', '\n'})
	if len(proofParts) < 2 {
		return fmt.Errorf("invalid proof, too few parts")
	}
	// Reapply final newline to split parts.
	for i := range proofParts[:len(proofParts)-1] {
		// Alternatively, could re-extend the slice to avoid an allocation.
		//
		// 	proofParts[i] = proofParts[i][:len(proofParts[i])+1]
		proofParts[i] = append(proofParts[i], '\n')
	}

	p := ascii.NewParser(bytes.NewBuffer(proofParts[0]))
	version, err := p.GetInt("version")
	if err != nil {
		return fmt.Errorf("invalid version line: %v", err)
	}
	if version != SigsumProofVersion {
		return fmt.Errorf("unexpected version %d, wanted %d", version, SigsumProofVersion)
	}

	sp.LogKeyHash, err = p.GetHash("log")
	if err != nil {
		return fmt.Errorf("invalid log line: %v", err)
	}
	if err := sp.Leaf.Parse(p); err != nil {
		return err
	}
	if err := p.GetEOF(); err != nil {
		return err
	}

	if err := sp.TreeHead.FromASCII(bytes.NewBuffer(proofParts[1])); err != nil {
		return err
	}
	if sp.TreeHead.Size == 0 {
		return fmt.Errorf("invalid tree: empty")
	}
	if sp.TreeHead.Size == 1 {
		if len(proofParts) != 2 {
			return fmt.Errorf("too many parts")
		}
		sp.Inclusion = types.InclusionProof{}
		return nil
	}
	if len(proofParts) != 3 {
		return fmt.Errorf("too few parts")
	}
	return sp.Inclusion.FromASCII(bytes.NewBuffer(proofParts[2]))
}

func (sp *SigsumProof) ToASCII(w io.Writer) error {
	if err := ascii.WriteInt(w, "version", SigsumProofVersion); err != nil {
		return err
	}
	if err := ascii.WriteHash(w, "log", &sp.LogKeyHash); err != nil {
		return err
	}
	if err := sp.Leaf.ToASCII(w); err != nil {
		return err
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	if err := sp.TreeHead.ToASCII(w); err != nil {
		return err
	}
	if sp.TreeHead.Size <= 1 {
		return nil
	}
	// Empty line as separator.
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	return sp.Inclusion.ToASCII(w)
}

func (sp *SigsumProof) Verify(msg *crypto.Hash, submitKey *crypto.PublicKey, policy *policy.Policy) error {
	checksum := crypto.HashBytes(msg[:])
	leaf, err := sp.Leaf.ToLeaf(&checksum)
	if err != nil {
		return err
	}
	if sp.Leaf.KeyHash != crypto.HashBytes(submitKey[:]) {
		return fmt.Errorf("unexpected submit key hash")
	}
	if !leaf.Verify(submitKey) {
		return fmt.Errorf("leaf signature not valid")
	}
	if err := policy.VerifyCosignedTreeHead(&sp.LogKeyHash, &sp.TreeHead); err != nil {
		return err
	}
	leafHash := leaf.ToHash()
	return sp.Inclusion.Verify(&leafHash, &sp.TreeHead.TreeHead)
}

func (sp *SigsumProof) VerifyNoCosignatures(msg *crypto.Hash, submitKey *crypto.PublicKey, logKey *crypto.PublicKey) error {
	policy, err := policy.NewKofNPolicy([]crypto.PublicKey{*logKey}, nil, 0)
	if err != nil {
		return fmt.Errorf("internal error: %v", err)
	}
	return sp.Verify(msg, submitKey, policy)
}
