package requests

import (
	"bytes"
	"reflect"
	"testing"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

func TestAddTreeHeadToASCII(t *testing.T) {
	req := validAddTreeHead()
	buf := bytes.Buffer{}
	if err := req.ToASCII(&buf); err != nil {
		t.Fatalf("ToASCII failed: %v", err)
	}
	if got, want := buf.String(), validAddTreeHeadASCII(); got != want {
		t.Errorf("unexpected ToASCII, got: %q, want: %q", got, want)
	}
}

func TestAddTreeHeadFromASCII(t *testing.T) {
	var req AddTreeHead
	if err := req.FromASCII(bytes.NewBufferString(validAddTreeHeadASCII())); err != nil {
		t.Errorf("FromASCII failed: %v", err)
	} else if got, want := req, validAddTreeHead(); !reflect.DeepEqual(got, want) {
		t.Errorf("unexpected FromASCII, got: %#v, want: %#v", got, want)
	}
}

func validAddTreeHead() AddTreeHead {
	return AddTreeHead{
		KeyHash: crypto.Hash{1},
		TreeHead: types.SignedTreeHead{
			TreeHead: types.TreeHead{
				Size:     2,
				RootHash: crypto.Hash{2},
			},
			Signature: crypto.Signature{3},
		},
		OldSize: 1,
		Proof:   types.ConsistencyProof{Path: []crypto.Hash{crypto.Hash{4}}},
	}
}

func validAddTreeHeadASCII() string {
	return `key_hash=0100000000000000000000000000000000000000000000000000000000000000
size=2
root_hash=0200000000000000000000000000000000000000000000000000000000000000
signature=03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
old_size=1
node_hash=0400000000000000000000000000000000000000000000000000000000000000
`
}
