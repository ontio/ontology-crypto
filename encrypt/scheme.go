package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strings"
)

type EciesScheme byte
type Hasher func() hash.Hash                   // hash function
type Cipher func([]byte) (cipher.Block, error) // symmetric cipher

const (
	AES128withSHA256 EciesScheme = iota
	AES256withSHA256
	AES256withSHA384
	AES256withSHA512
)

var names []string = []string{
	"AES128withSHA256",
	"AES256withSHA256",
	"AES256withSHA384",
	"AES256withSHA512",
}

func (s EciesScheme) Name() string {
	if int(s) >= len(names) {
		panic(fmt.Sprintf("unknown scheme value %v", s))
	}
	return names[s]
}

func GetScheme(name string) (EciesScheme, error) {
	for i, v := range names {
		if strings.ToUpper(v) == strings.ToUpper(name) {
			return EciesScheme(i), nil
		}
	}

	return 0, errors.New("unknown signature scheme " + name)
}

func GetHash(scheme EciesScheme) Hasher {
	switch scheme {
	case AES128withSHA256:
		return sha256.New
	case AES256withSHA256:
		return sha256.New
	case AES256withSHA384:
		return sha512.New
	case AES256withSHA512:
		return sha512.New
	}
	return nil
}

func GetKeyLen(scheme EciesScheme) int {
	switch scheme {
	case AES128withSHA256:
		return 16
	case AES256withSHA256:
		return 32
	case AES256withSHA384:
		return 32
	case AES256withSHA512:
		return 32
	}
	return 0
}

func GetBlockSize(scheme EciesScheme) int {
	switch scheme {
	case AES128withSHA256:
		return 16
	case AES256withSHA256:
		return 16
	case AES256withSHA384:
		return 16
	case AES256withSHA512:
		return 16
	}
	return 0
}

func GetCipher(scheme EciesScheme) Cipher {
	switch scheme {
	case AES128withSHA256:
		return aes.NewCipher
	case AES256withSHA256:
		return aes.NewCipher
	case AES256withSHA384:
		return aes.NewCipher
	case AES256withSHA512:
		return aes.NewCipher
	}
	return nil
}
