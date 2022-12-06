package requests

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/ascii"
	"sigsum.org/sigsum-go/pkg/crypto"
)

type Leaf struct {
	Message   crypto.Hash
	Signature crypto.Signature
	PublicKey crypto.PublicKey
}

type Leaves struct {
	StartIndex uint64
	EndIndex   uint64
}

type InclusionProof struct {
	Size uint64
	LeafHash crypto.Hash
}

type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
}

// TODO: Replace with type alias (golang 1.9 feature)
type Cosignature struct {
	KeyHash   crypto.Hash
	Signature crypto.Signature
}

func (req *Leaf) ToASCII(w io.Writer) error {
	if err := ascii.WriteLineHex(w, "message", req.Message[:]); err != nil {
		return err
	}
	if err := ascii.WriteLineHex(w, "signature", req.Signature[:]); err != nil {
		return err
	}
	return ascii.WriteLineHex(w, "public_key", req.PublicKey[:])
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *Leaves) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.StartIndex, req.EndIndex)
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *InclusionProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%s", req.Size, hex.EncodeToString(req.LeafHash[:]))
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *ConsistencyProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.OldSize, req.NewSize)
}

func (req *Cosignature) ToASCII(w io.Writer) error {
	return ascii.WriteLineHex(w, "cosignature", req.KeyHash[:], req.Signature[:])
}

func (req *Leaf) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	var err error
	req.Message, err = p.GetHash("message")
	if err != nil {
		return err
	}
	req.Signature, err = p.GetSignature("signature")
	if err != nil {
		return err
	}
	req.PublicKey, err = p.GetPublicKey("public_key")
	if err != nil {
		return err
	}
	return p.GetEOF()
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *Leaves) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	startIndex := split[len(split)-2]
	if req.StartIndex, err = strconv.ParseUint(startIndex, 10, 64); err != nil {
		return err
	}
	endIndex := split[len(split)-1]
	if req.EndIndex, err = strconv.ParseUint(endIndex, 10, 64); err != nil {
		return err
	}
	return nil
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *InclusionProof) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	treeSize := split[len(split)-2]
	if req.Size, err = strconv.ParseUint(treeSize, 10, 64); err != nil {
		return err
	}
	req.LeafHash, err = crypto.HashFromHex(split[len(split)-1])
	return err
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *ConsistencyProof) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	oldSize := split[len(split)-2]
	if req.OldSize, err = strconv.ParseUint(oldSize, 10, 64); err != nil {
		return err
	}
	newSize := split[len(split)-1]
	if req.NewSize, err = strconv.ParseUint(newSize, 10, 64); err != nil {
		return err
	}
	return nil
}

func (req *Cosignature) FromASCII(r io.Reader) error {
	p := ascii.NewParser(r)
	v, err := p.GetValues("cosignature", 2)
	if err != nil {
		return err
	}
	req.KeyHash, err = crypto.HashFromHex(v[0])
	if err != nil {
		return err
	}
	req.Signature, err = crypto.SignatureFromHex(v[1])
	if err != nil {
		return err
	}
	return p.GetEOF()
}
