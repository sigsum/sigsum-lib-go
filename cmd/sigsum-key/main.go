package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/internal/ssh"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
)

type GenSettings struct {
	outputFile string
}

type VerifySettings struct {
	keyFile       string
	signatureFile string
	namespace     string
}

type SignSettings struct {
	keyFile    string
	outputFile string
	namespace  string
	sshFormat  bool
}

type ExportSettings struct {
	keyFile string
}

func main() {
	const usage = `sigsum-key sub commands:

  sigsum-key help 
    Display this help.

  sigsum-key gen -o KEY-FILE
    Generate a new key pair. Private key is stored in the given
    KEY-FILE, hex-encoded. Corresponding public key file gets a ".pub"
    suffix, and is written in OpenSSH format.

  sigsum-key verify -k KEY -s SIGNATURE [-n NAMESPACE] < MSG
    KEY and SIGNATURE are file names.
    NAMESPACE is a string, default being "signed-tree-head:v0@sigsum.org"

  sigsum-key sign -k KEY [-o SIGNATURE] [-n NAMESPACE] [--ssh] < MSG
    KEY and SIGNATURE are file names (by default, signature is written
    to stdout). NAMESPACE is a string, default being
    "tree-leaf:v0@sigsum.org". If --ssh is provided, produce an ssh
    signature file, otherwise raw hex.

  sigsum-key hash -k KEY
    KEY is filename of a public key. Outputs hex-encoded key hash.

  sigsum-key hex -k KEY
    KEY is filename of a public key. Outputs hex-encoded raw key.
`
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal(usage)
	}

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	default:
		log.Fatal(usage)
	case "help":
		log.Print(usage)
		os.Exit(0)
	case "gen":
		var settings GenSettings
		settings.parse(args)
		pub, signer, err := crypto.NewKeyPair()
		if err != nil {
			log.Fatalf("generating key failed: %v\n", err)
		}
		writeKeyFiles(settings.outputFile, &pub, signer)
	case "verify":
		var settings VerifySettings
		settings.parse(args)
		publicKey, err := key.ReadPublicKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		signature := readSignatureFile(settings.signatureFile,
			&publicKey, settings.namespace)
		hash, err := crypto.HashFile(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read stdin: %v\n", err)
		}

		if !crypto.Verify(&publicKey,
			ssh.SignedDataFromHash(settings.namespace, &hash),
			&signature) {
			log.Fatalf("signature is not valid\n")
		}
	case "sign":
		var settings SignSettings
		settings.parse(args)
		signer, err := key.ReadPrivateKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		hash, err := crypto.HashFile(os.Stdin)
		if err != nil {
			log.Fatalf("failed to read stdin: %v\n", err)
		}
		signature, err := signer.Sign(ssh.SignedDataFromHash(settings.namespace, &hash))
		if err != nil {
			log.Fatalf("signing failed: %v", err)
		}
		public := signer.Public()
		writeSignatureFile(settings.outputFile, settings.sshFormat,
			&public, settings.namespace, &signature)
	case "hash":
		var settings ExportSettings
		settings.parse(args)
		publicKey, err := key.ReadPublicKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", crypto.HashBytes(publicKey[:]))
	case "hex":
		var settings ExportSettings
		settings.parse(args)
		publicKey, err := key.ReadPublicKeyFile(settings.keyFile)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", publicKey[:])
	}
}

func (s *GenSettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.outputFile, "o", "", "Output file")

	flags.Parse(args)

	if len(s.outputFile) == 0 {
		log.Printf("output file (-o option) missing")
		os.Exit(1)
	}
}

func (s *VerifySettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.keyFile, "k", "", "Key file")
	flags.StringVar(&s.signatureFile, "s", "", "Signature file")
	flags.StringVar(&s.namespace, "n", "signed-tree-head:v0@sigsum.org", "Signature namespace")

	flags.Parse(args)

	if len(s.keyFile) == 0 {
		log.Printf("key file (-k option) missing")
		os.Exit(1)
	}
	if len(s.signatureFile) == 0 {
		log.Printf("signature file (-s option) missing")
		os.Exit(1)
	}
}

func (s *SignSettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.keyFile, "k", "", "Key file")
	flags.StringVar(&s.outputFile, "o", "", "Signature output file")
	flags.StringVar(&s.namespace, "n", "tree-leaf:v0@sigsum.org", "Signature namespace")
	flags.BoolVar(&s.sshFormat, "ssh", false, "Use OpenSSH format for public key")

	flags.Parse(args)

	if len(s.keyFile) == 0 {
		log.Fatalf("key file (-k option) missing")
	}
}

func (s *ExportSettings) parse(args []string) {
	flags := flag.NewFlagSet("", flag.ExitOnError)
	flags.StringVar(&s.keyFile, "k", "", "Key file")

	flags.Parse(args)

	if len(s.keyFile) == 0 {
		log.Printf("key file (-k option) missing")
		os.Exit(1)
	}
}

// If outputFile is non-empty: open file, pass to f, and automatically
// close it after f returns. Otherwise, just pass os.Stdout to f. Also
// exit program on error from f.
func withOutput(outputFile string, mode os.FileMode, f func(io.Writer) error) {
	file := os.Stdout
	if len(outputFile) > 0 {
		var err error
		file, err = os.OpenFile(outputFile,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			log.Fatalf("failed to open file '%v': %v", outputFile, err)
		}
		defer file.Close()
	}
	err := f(file)
	if err != nil {
		log.Fatalf("writing output failed: %v", err)
	}
}

func writeKeyFiles(outputFile string, pub *crypto.PublicKey, signer *crypto.Ed25519Signer) {
	withOutput(outputFile, 0600, func(f io.Writer) error {
		return ssh.WritePrivateKeyFile(f, signer)
	})
	if len(outputFile) > 0 {
		// Openssh insists that also public key files have
		// restrictive permissions.
		withOutput(outputFile+".pub", 0600,
			func(f io.Writer) error {
				_, err := io.WriteString(f, ssh.FormatPublicEd25519(pub))
				return err
			})
	}
}

func writeSignatureFile(outputFile string, sshFormat bool,
	public *crypto.PublicKey, namespace string, signature *crypto.Signature) {
	withOutput(outputFile, 0644, func(f io.Writer) error {
		if sshFormat {
			return ssh.WriteSignatureFile(f, public, namespace, signature)
		}
		_, err := fmt.Fprintf(f, "%x\n", signature[:])
		return err
	})
}

func readSignatureFile(fileName string,
	pub *crypto.PublicKey, namespace string) crypto.Signature {
	contents, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("reading file %q failed: %v", fileName, err)
	}
	signature, err := ssh.ParseSignatureFile(contents, pub, namespace)
	if err == ssh.NoPEMError {
		signature, err = crypto.SignatureFromHex(strings.TrimSpace(string(contents)))
	}
	if err != nil {
		log.Fatal(err)
	}
	return signature
}
