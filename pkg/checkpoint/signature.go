package checkpoint

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/types"
)

// See https://github.com/C2SP/C2SP/blob/signed-note/v1.0.0-rc.1/signed-note.md
type signatureType byte

const (
	sigTypeEd25519     signatureType = 0x01
	sigTypeCosignature signatureType = 0x04
)

var ErrUnwantedSignature = errors.New("unwanted signature")

type KeyId [4]byte

func makeKeyId(keyName string, sigType signatureType, publicKey *crypto.PublicKey) (res KeyId) {
	hash := crypto.HashBytes(bytes.Join([][]byte{[]byte(keyName), []byte{0xA, byte(sigType)}, publicKey[:]}, nil))
	copy(res[:], hash[:4])
	return
}

func NewLogKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return makeKeyId(keyName, sigTypeEd25519, publicKey)
}

func NewWitnessKeyId(keyName string, publicKey *crypto.PublicKey) (res KeyId) {
	return makeKeyId(keyName, sigTypeCosignature, publicKey)
}

func writeNoteSignature(w io.Writer, keyName string, keyId KeyId, signature []byte) error {
	_, err := fmt.Fprintf(w, "\u2014 %s %s\n", keyName,
		base64.StdEncoding.EncodeToString(bytes.Join([][]byte{keyId[:], signature[:]}, nil)))
	return err
}

// Input is a single signature line, with no trailing newline
// character. Returns key name, key id and base64-decoded signature blob.
func parseNoteSignature(line string, signatureSize int) (string, KeyId, []byte, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 3 || fields[0] != "\u2014" {
		return "", KeyId{}, nil, fmt.Errorf("invalid signature line %q", line)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		return "", KeyId{}, nil, err
	}
	if len(blob) != 4+signatureSize {
		return "", KeyId{}, nil, ErrUnwantedSignature
	}
	var keyId KeyId
	copy(keyId[:], blob[:4])
	return fields[1], keyId, blob[4:], nil
}

func WriteEd25519Signature(w io.Writer, origin string, keyId KeyId, signature *crypto.Signature) error {
	return writeNoteSignature(w, origin, keyId, signature[:])
}

// Input is a single signature line, with no trailing newline
// character. If the line carries the right keyName and has a size
// consistent with an Ed25519 signature line, returns the keyId and
// signature. If line is syntactically valid but doesn't match these
// requirements, ErrUnwantedSignature is returned.
func ParseEd25519SignatureLine(line, keyName string) (KeyId, crypto.Signature, error) {
	name, keyId, blob, err := parseNoteSignature(line, crypto.SignatureSize)
	if err != nil {
		return KeyId{}, crypto.Signature{}, err
	}
	if name != keyName {
		return KeyId{}, crypto.Signature{}, ErrUnwantedSignature
	}
	var signature crypto.Signature
	copy(signature[:], blob)

	return keyId, signature, nil
}

func WriteCosignature(w io.Writer, keyName string, keyId KeyId, timestamp uint64, sig *crypto.Signature) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], timestamp)
	return writeNoteSignature(w, keyName, keyId, bytes.Join([][]byte{buf[:], sig[:]}, nil))
}

// Looks for a signature with a particular witness public key, and
// ignores the key name on the line, except that it is used to match
// the keyId. Does not verify the signature.
func ParseCosignature(line string, publicKey *crypto.PublicKey) (types.Cosignature, error) {
	keyName, keyId, blob, err := parseNoteSignature(line, 8+crypto.SignatureSize)
	if err != nil {
		return types.Cosignature{}, err
	}
	if keyId != makeKeyId(keyName, sigTypeCosignature, publicKey) {
		return types.Cosignature{}, ErrUnwantedSignature
	}
	cs := types.Cosignature{
		KeyHash:   crypto.HashBytes(publicKey[:]),
		Timestamp: binary.BigEndian.Uint64(blob[:8]),
	}
	copy(cs.Signature[:], blob[8:])
	return cs, nil
}
