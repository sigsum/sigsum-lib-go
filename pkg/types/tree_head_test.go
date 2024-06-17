package types

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"

	"sigsum.org/sigsum-go/internal/mocks/signer"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

const (
	testCosignTimestamp uint64 = 72623859790382856
)

func TestTreeHeadToCheckpoint(t *testing.T) {
	desc := "valid"
	pub := crypto.PublicKey{}
	keyHash := crypto.HashBytes(pub[:])
	if got, want := validTreeHead(t).toCheckpoint(&keyHash),
		validTreeHeadCheckpoint(t); got != want {
		t.Errorf("got tree head checkpoint\n\t%q\nbut wanted\n\t%q\nin test %q\n", got, want, desc)
	}
}

func TestTreeHeadToCosignedData(t *testing.T) {
	desc := "valid"
	pub := crypto.PublicKey{}
	keyHash := crypto.HashBytes(pub[:])
	if got, want := validTreeHead(t).toCosignedData(&keyHash, testCosignTimestamp),
		validTreeHeadCosignedData(t); got != want {
		t.Errorf("got tree head checkpoint\n\t%q\nbut wanted\n\t%q\nin test %q\n", got, want, desc)
	}
}

func TestTreeHeadSign(t *testing.T) {
	for _, table := range []struct {
		desc    string
		th      *TreeHead
		signer  crypto.Signer
		wantSig *crypto.Signature
		wantErr bool
	}{
		{
			desc:    "invalid: signer error",
			th:      validTreeHead(t),
			signer:  &signer.Signer{PublicKey: *newPubBufferInc(t), Signature: *newSigBufferInc(t), Error: fmt.Errorf("signing error")},
			wantErr: true,
		},
		{
			desc:    "valid",
			th:      validTreeHead(t),
			signer:  &signer.Signer{PublicKey: *newPubBufferInc(t), Signature: *newSigBufferInc(t)},
			wantSig: newSigBufferInc(t),
		},
	} {
		sth, err := table.th.Sign(table.signer)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}

		wantSTH := SignedTreeHead{
			TreeHead:  *table.th,
			Signature: *table.wantSig,
		}
		if got, want := sth, wantSTH; sth != wantSTH {
			t.Errorf("got sth\n\t%v\nbut wanted\n\t%v\nin test %q", got, want, table.desc)
		}
	}
}

func TestSignedTreeHeadToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validSignedTreeHead(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validSignedTreeHeadASCII(t); got != want {
		t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestSignedTreeHeadFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *SignedTreeHead
	}{
		{
			desc:       "invalid: not a signed tree head (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validSignedTreeHeadASCII(t) + "key=4"),
			wantErr:    true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validSignedTreeHeadASCII(t)),
			want:       validSignedTreeHead(t),
		},
	} {
		var sth SignedTreeHead
		err := sth.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := sth, *table.want; got != want {
			t.Errorf("got signed tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestTreeHeadSignAndVerify(t *testing.T) {
	th := validTreeHead(t)
	pub, signer := newKeyPair(t)

	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}

	if !sth.Verify(&pub) {
		t.Errorf("failed verifying a valid signed tree head")
	}

	sth.Size += 1
	if sth.Verify(&pub) {
		t.Errorf("succeeded verifying an invalid signed tree head")
	}
}

func TestSignedTreeHeadVerify(t *testing.T) {
	pub := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ")
	sth := SignedTreeHead{
		TreeHead: TreeHead{
			Size:     4,
			RootHash: mustHashFromHex(t, "7bca01e88737999fde5c1d6ecac27ae3cb49e14f21bcd3e7245c276877b899c9"),
		},
		Signature: mustSignatureFromHex(t, "c60e5151b9d0f0efaf57022c0ec306c0f0275afef69333cc89df4fda328c87949fcfa44564f35020938a4cd6c1c50bc0349b2f54b82f5f6104b9cd52be2cd90e"),
	}
	if !sth.Verify(&pub) {
		t.Errorf("failed verifying a valid signed tree head")
	}

	sth.Size += 1
	if sth.Verify(&pub) {
		t.Errorf("succeeded verifying an invalid signed tree head")
	}
}

func TestSignedTreeHeadVerifyVersion0(t *testing.T) {
	// Example based on a run of tests/sigsum-submit-test
	pub := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICLAkeP3VJfvGQFcXa8UORDiDNpylbD9Hd+DglaG7+ym")
	sth := SignedTreeHead{
		TreeHead: TreeHead{
			Size:     4,
			RootHash: mustHashFromHex(t, "84ec3e1ba5433358988ac74bed33a30bda42cc983b87e4940a423c2d84890f0f"),
		},
		Signature: mustSignatureFromHex(t, "7e2084ded0f7625136e6c811ac7eae2cb79613cadb12a6437b391cdae3a5c915dcd30b5b5fe4fbf417a2d607a4cfcb3612d7fd4ffe9453c0d29ec002a6d47709"),
	}
	if !sth.VerifyVersion0(&pub) {
		t.Errorf("failed verifying a valid signed tree head")
	}

	sth.Size += 1
	if sth.VerifyVersion0(&pub) {
		t.Errorf("succeeded verifying an invalid signed tree head")
	}
}

func TestCosignatureToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validCosignature(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validCosignatureASCII(t); got != want {
		t.Errorf("got cosignature request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestCosignatureFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *Cosignature
	}{
		{
			desc:       "invalid: not a cosignature request (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validCosignatureASCII(t) + "key=4"),
			wantErr:    true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validCosignatureASCII(t)),
			want:       validCosignature(t),
		},
	} {
		var req Cosignature
		err := req.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := req, *table.want; got != want {
			t.Errorf("got cosignature request\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func TestCosignAndVerify(t *testing.T) {
	th := *validTreeHead(t)
	pub, signer := newKeyPair(t)
	keyHash := crypto.HashBytes(pub[:])
	logKeyHash := *newHashBufferInc(t)

	cosignature, err := th.Cosign(signer, &logKeyHash, testCosignTimestamp)
	if err != nil {
		t.Fatal(err)
	}

	if cosignature.Timestamp != testCosignTimestamp {
		t.Errorf("unexpected cosignature timestamp, wanted %d, got %d",
			testCosignTimestamp, cosignature.Timestamp)
	}
	if cosignature.KeyHash != keyHash {
		t.Errorf("unexpected cosignature keyhash, wanted %x, got %x",
			keyHash, cosignature.KeyHash)
	}
	if !cosignature.Verify(&pub, &logKeyHash, &th) {
		t.Errorf("failed verifying a valid cosignature")
	}

	// Test mutation of signed items.
	for _, f := range [](func() (string, TreeHead, Cosignature, crypto.Hash)){
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mTh := th
			mTh.Size++
			return "bad size", mTh, cosignature, logKeyHash
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mCs := cosignature
			mCs.Timestamp++
			return "bad timestamp", th, mCs, logKeyHash
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mCs := cosignature
			mCs.KeyHash[2]++
			return "bad cs key hash", th, mCs, logKeyHash
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			mKh := logKeyHash
			mKh[3]++
			return "bad log key hash", th, cosignature, mKh
		},
		func() (string, TreeHead, Cosignature, crypto.Hash) {
			return "", th, cosignature, logKeyHash
		},
	} {
		desc, mTh, mCs, mLogHash := f()
		valid := mCs.Verify(&pub, &mLogHash, &mTh)
		if len(desc) > 0 && valid {
			t.Errorf("%s: succeeded verifying invalid cosignature", desc)
		} else if len(desc) == 0 && !valid {
			t.Errorf("internal test failure, failed to verify unmodified cosignature")
		}
	}
}

func TestCosignedTreeHeadToASCII(t *testing.T) {
	desc := "valid"
	buf := bytes.Buffer{}
	if err := validCosignedTreeHead(t).ToASCII(&buf); err != nil {
		t.Fatalf("got error true but wanted false in test %q: %v", desc, err)
	}
	if got, want := buf.String(), validCosignedTreeHeadASCII(t); got != want {
		t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, desc)
	}
}

func TestCosignedTreeHeadFromASCII(t *testing.T) {
	for _, table := range []struct {
		desc       string
		serialized io.Reader
		wantErr    bool
		want       *CosignedTreeHead
	}{
		{
			desc:       "invalid: not a cosigned tree head (unexpected key-value pair)",
			serialized: bytes.NewBufferString(validCosignedTreeHeadASCII(t) + "key=4"),
			wantErr:    true,
		},
		{
			desc: "invalid: not a cosigned tree head (not enough cosignatures)",
			serialized: bytes.NewBufferString(validCosignedTreeHeadASCII(t) +
				fmt.Sprintf("key_hash=%x\n", crypto.Hash{})),
			wantErr: true,
		},
		{
			desc:       "valid",
			serialized: bytes.NewBufferString(validCosignedTreeHeadASCII(t)),
			want:       validCosignedTreeHead(t),
		},
	} {
		var cth CosignedTreeHead
		err := cth.FromASCII(table.serialized)
		if got, want := err != nil, table.wantErr; got != want {
			t.Errorf("got error %v but wanted %v in test %q: %v", got, want, table.desc, err)
		}
		if err != nil {
			continue
		}
		if got, want := &cth, table.want; !reflect.DeepEqual(got, want) {
			t.Errorf("got cosigned tree head\n\t%v\nbut wanted\n\t%v\nin test %q\n", got, want, table.desc)
		}
	}
}

func validTreeHead(t *testing.T) *TreeHead {
	return &TreeHead{
		Size:     257,
		RootHash: *newHashBufferInc(t),
	}
}

func validTreeHeadCheckpoint(t *testing.T) string {
	return `
sigsum.org/v1/tree/66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
257
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
`[1:]
}

func validTreeHeadCosignedData(t *testing.T) string {
	return `
cosignature/v1
time 72623859790382856
sigsum.org/v1/tree/66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925
257
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
`[1:]
}

func validSignedTreeHead(t *testing.T) *SignedTreeHead {
	t.Helper()
	return &SignedTreeHead{
		TreeHead: TreeHead{
			Size:     2,
			RootHash: *newHashBufferInc(t),
		},
		Signature: *newSigBufferInc(t),
	}
}

func validSignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n",
		"size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
	)
}

func validCosignature(t *testing.T) *Cosignature {
	t.Helper()
	return &Cosignature{
		Signature: *newSigBufferInc(t),
		Timestamp: 1,
		KeyHash:   *newHashBufferInc(t),
	}
}

func validCosignatureASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%x %d %x\n",
		"cosignature", newHashBufferInc(t)[:], 1, newSigBufferInc(t)[:])
}

func validCosignedTreeHead(t *testing.T) *CosignedTreeHead {
	t.Helper()
	return &CosignedTreeHead{
		SignedTreeHead: SignedTreeHead{
			TreeHead: TreeHead{
				Size:     2,
				RootHash: *newHashBufferInc(t),
			},
			Signature: *newSigBufferInc(t),
		},
		Cosignatures: []Cosignature{
			Cosignature{},
			Cosignature{
				KeyHash:   *newHashBufferInc(t),
				Timestamp: 1,
				Signature: *newSigBufferInc(t),
			},
		},
	}
}

func validCosignedTreeHeadASCII(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s=%d\n%s=%x\n%s=%x\n%s=%x %d %x\n%s=%x %d %x\n",
		"size", 2,
		"root_hash", newHashBufferInc(t)[:],
		"signature", newSigBufferInc(t)[:],
		"cosignature", crypto.Hash{}, 0, crypto.Signature{},
		"cosignature", newHashBufferInc(t)[:], 1, newSigBufferInc(t)[:],
	)
}

func mustParsePublicKey(t *testing.T, sshKey string) crypto.PublicKey {
	pub, err := key.ParsePublicKey(sshKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
func mustHashFromHex(t *testing.T, hex string) crypto.Hash {
	h, err := crypto.HashFromHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func mustSignatureFromHex(t *testing.T, hex string) crypto.Signature {
	s, err := crypto.SignatureFromHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
