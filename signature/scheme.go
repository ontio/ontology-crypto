package signature

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/OntologyNetwork/ont-crypto/sm3"
)

type SignatureScheme byte

const (
	SHA224withECDSA SignatureScheme = iota
	SHA256withECDSA
	SHA384withECDSA
	SHA512withECDSA
	SHA3_224withECDSA
	SHA3_256withECDSA
	SHA3_384withECDSA
	SHA3_512withECDSA
	RIPEMD160withECDSA

	SM3withSM2
)

var names []string = []string{
	"SHA224withECDSA",
	"SHA256withECDSA",
	"SHA384withECDSA",
	"SHA512withECDSA",
	"SHA3-224withECDSA",
	"SHA3-256withECDSA",
	"SHA3-384withECDSA",
	"SHA3-512withECDSA",
	"RIPEMD160withECDSA",
	"SM3withSM2",
}

func (s SignatureScheme) Name() string {
	if int(s) >= len(names) {
		panic(fmt.Sprintf("unknown scheme value %v", s))
	}
	return names[s]
}

func GetScheme(name string) (SignatureScheme, error) {
	for i, v := range names {
		if strings.ToUpper(v) == strings.ToUpper(name) {
			return SignatureScheme(i), nil
		}
	}

	return 0, errors.New("unknown signature scheme " + name)
}

func GetHash(scheme SignatureScheme) hash.Hash {
	switch scheme {
	case SHA224withECDSA:
		return crypto.SHA224.New()
	case SHA256withECDSA:
		return crypto.SHA256.New()
	case SHA384withECDSA:
		return crypto.SHA384.New()
	case SHA512withECDSA:
		return crypto.SHA512.New()
	case SHA3_224withECDSA:
		return crypto.SHA3_224.New()
	case SHA3_256withECDSA:
		return crypto.SHA3_256.New()
	case SHA3_384withECDSA:
		return crypto.SHA3_384.New()
	case SHA3_512withECDSA:
		return crypto.SHA3_512.New()
	case RIPEMD160withECDSA:
		return crypto.RIPEMD160.New()
	case SM3withSM2:
		return sm3.New()
	}
	return nil
}
