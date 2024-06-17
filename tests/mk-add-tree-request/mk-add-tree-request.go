package main

// Program to generate a witness add-tree request, from a
// deterministically built tree.
import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s old-size new-size < private-key",
			os.Args[0])
	}
	oldSize, err := strconv.ParseUint(os.Args[1], 10, 63)
	if err != nil || oldSize < 0 {
		log.Fatalf("Invalid old size %q", os.Args[1])
	}
	newSize, err := strconv.ParseUint(os.Args[2], 10, 63)
	if err != nil || newSize < oldSize {
		log.Fatalf("Invalid old size %q", os.Args[1])
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("reading key from stdin failed: %v", err)
	}
	ascii := string(data)
	signer, err := key.ParsePrivateKey(ascii)
	if err != nil {
		log.Fatalf("parsing public key failed: %v", err)
	}
	pub := signer.Public()
	t := merkle.NewTree()
	for i := uint64(0); i < newSize; i++ {
		h := crypto.Hash{}
		binary.BigEndian.PutUint64(h[:8], i)
		if !t.AddLeafHash(&h) {
			log.Fatalf("Unexpected leaf duplicate for leaf %d", i)
		}
	}
	th := types.TreeHead{Size: t.Size(), RootHash: t.GetRootHash()}
	if th.Size != newSize {
		panic("internal error")
	}
	sth, err := th.Sign(signer)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := t.ProveConsistency(oldSize, newSize)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := fmt.Printf("key_hash=%x\n", crypto.HashBytes(pub[:])); err != nil {
		log.Fatal(err)
	}
	if err := sth.ToASCII(os.Stdout); err != nil {
		log.Fatal(err)
	}
	if _, err := fmt.Printf("old_size=%d\n", oldSize); err != nil {
		log.Fatal(err)
	}
	if len(proof) > 0 {
		if err := (&types.ConsistencyProof{Path: proof}).ToASCII(os.Stdout); err != nil {
			log.Fatal(err)
		}
	}
}
