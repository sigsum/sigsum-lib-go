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
	Message   crypto.Hash      `ascii:"message"`
	Signature crypto.Signature `ascii:"signature"`
	PublicKey crypto.PublicKey `ascii:"public_key"`
}

type Leaves struct {
	StartSize uint64
	EndSize   uint64
}

type InclusionProof struct {
	TreeSize uint64
	LeafHash crypto.Hash
}

type ConsistencyProof struct {
	OldSize uint64
	NewSize uint64
}

type Cosignature struct {
	Cosignature crypto.Signature
	KeyHash     crypto.Hash
}

func (req *Leaf) ToASCII(w io.Writer) error {
	if err := ascii.WriteLineHex(w, "message", req.Message[:]); err != nil{
		return err
	}
	if err := ascii.WriteLineHex(w, "signature", Signature[:]); err != nil {
		return err
	}
	return ascii.WriteLineHex(w, "public_key", req.PublicKey[:])
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *Leaves) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.StartSize, req.EndSize)
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *InclusionProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%s", req.TreeSize, hex.EncodeToString(req.LeafHash[:]))
}

// ToURL encodes request parameters at the end of a slash-terminated URL
func (req *ConsistencyProof) ToURL(url string) string {
	return url + fmt.Sprintf("%d/%d", req.OldSize, req.NewSize)
}

func (req *Cosignature) ToASCII(w io.Writer) error {
	return fmt.Errorf("not implemented") // XXX ascii.StdEncoding.Serialize(w, req)
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
	return nil;
}

// FromURL parses request parameters from a URL that is not slash-terminated
func (req *Leaves) FromURL(url string) (err error) {
	split := strings.Split(url, "/")
	if len(split) < 2 {
		return fmt.Errorf("not enough input")
	}
	startSize := split[len(split)-2]
	if req.StartSize, err = strconv.ParseUint(startSize, 10, 64); err != nil {
		return err
	}
	endSize := split[len(split)-1]
	if req.EndSize, err = strconv.ParseUint(endSize, 10, 64); err != nil {
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
	if req.TreeSize, err = strconv.ParseUint(treeSize, 10, 64); err != nil {
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
	return fmt.Errorf("not implemented") // XXX ascii.StdEncoding.Deserialize(r, req)
}
