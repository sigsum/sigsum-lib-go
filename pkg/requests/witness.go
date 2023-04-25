package requests

import (
	"fmt"
	"io"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

type AddTreeHead struct {
	KeyHash  crypto.Hash
	TreeHead types.SignedTreeHead
	OldSize  uint64
	Proof    types.ConsistencyProof
}

func (req *AddTreeHead) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	req.KeyHash, err = p.GetHash("key_hash")
	if err != nil {
		return err
	}
	if err := req.TreeHead.Parse(&p); err != nil {
		return err
	}
	req.OldSize, err = p.GetInt("old_size")
	if err != nil {
		return err
	}
	if req.OldSize > req.TreeHead.Size {
		return fmt.Errorf("invalid request, old_size(%d) > size(%d)",
			req.OldSize, req.TreeHead.Size)
	}
	// Cases of trivial consistency.
	if req.OldSize == 0 || req.OldSize == req.TreeHead.Size {
		return p.GetEOF()
	}
	return req.Proof.Parse(&p)
}

func (req *AddTreeHead) ToASCII(w io.Writer) error {
	if err := ascii.WriteHash(w, "key_hash", &req.KeyHash); err != nil {
		return err
	}
	if err := req.TreeHead.ToASCII(w); err != nil {
		return err
	}
	if err := ascii.WriteInt(w, "old_size", req.OldSize); err != nil {
		return err
	}
	return req.Proof.ToASCII(w)
}

type GetTreeSize struct {
	KeyHash crypto.Hash
}

func (req *GetTreeSize) ToURL(url string) string {
	return fmt.Sprintf("%s%x", url, req.KeyHash)
}