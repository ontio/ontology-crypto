package keypair

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"github.com/ontio/ontology-crypto/ec"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

const (
	// parameters used in scrypt
	n    = 16384
	r    = 8
	p    = 8
	klen = 64
)

// ProtectedKey stores the encrypted private key and related data
type ProtectedKey struct {
	Address string            `json:"address"`
	EncAlg  string            `json:"enc-alg"`
	Key     []byte            `json:"key"`
	Hash    string            `json:"hash"`
	Alg     string            `json:"algorithm"`
	Param   map[string]string `json:"parameters,omitempty"`
}

// Encrypt the private key with the given password.
// The password is used to derive a key via scrypt function.
// AES with CTR mode is used for encryption. The first 4 bytes of the derived
// key is used as the initial vector (IV), and the last 32 bytes is used as the
// encryption key.
func EncryptPrivateKey(pri PrivateKey, addr, pwd string) (*ProtectedKey, error) {
	var res = ProtectedKey{
		Address: addr,
		Hash:    "sha256",
		EncAlg:  "aes-256-ctr",
	}

	dkey, err := kdf(addr, pwd)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}
	iv := dkey[:16]
	ekey := dkey[32:]

	// Prepare the private key data for encryption
	var plaintext []byte
	switch t := pri.(type) {
	case *ec.PrivateKey:
		plaintext = t.D.Bytes()
		switch t.Algorithm {
		case ec.ECDSA:
			res.Alg = "ECDSA"
		case ec.SM2:
			res.Alg = "SM2"
		default:
			panic("unsupported ec algorithm")
		}
		res.Param = make(map[string]string)
		res.Param["curve"] = t.Params().Name
	case ed25519.PrivateKey:
		plaintext = []byte(t)
		res.Alg = "Ed25519"
	default:
		panic("unsupported key type")
	}

	ciphertext, err := ctrCipher(plaintext, ekey, iv)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}
	res.Key = ciphertext

	return &res, nil
}

// Decrypt the private key using the given password
func DecryptPrivateKey(prot *ProtectedKey, pwd string) (PrivateKey, error) {
	if prot == nil || len(pwd) == 0 {
		return nil, NewDecryptError("invalid argument")
	}

	// Check parameters
	if prot.EncAlg != "aes-256-ctr" {
		return nil, NewDecryptError("unsupported encryption algorithm")
	}

	// Derive key
	dkey, err := kdf(prot.Address, pwd)
	if err != nil {
		return nil, NewDecryptError(err.Error())
	}

	// Decryption, same process as encryption
	plaintext, err := ctrCipher(prot.Key, dkey[32:], dkey[:16])
	if err != nil {
		return nil, NewDecryptError(err.Error())
	}

	switch prot.Alg {
	case "ECDSA", "SM2":
		curve, err := GetNamedCurve(prot.Param["curve"])
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		pri := ec.PrivateKey{PrivateKey: ec.ConstructPrivateKey(plaintext, curve)}
		if prot.Alg == "ECDSA" {
			pri.Algorithm = ec.ECDSA
		} else if prot.Alg == "SM2" {
			pri.Algorithm = ec.SM2
		} else {
			return nil, NewDecryptError("unknown ec algorithm")
		}
		return &pri, nil
	case "Ed25519":
		if len(plaintext) != ed25519.PrivateKeySize {
			return nil, NewDecryptError("invalid Ed25519 private key length")
		}
		return ed25519.PrivateKey(plaintext), nil
	default:
		return nil, NewDecryptError("unknown key type")
	}
}

func kdf(addr, pwd string) ([]byte, error) {
	// Hash the address twice to get the salt
	digest := sha256.Sum256([]byte(addr))
	digest = sha256.Sum256(digest[:])
	// Derive the encryption key
	return scrypt.Key([]byte(pwd), digest[:4], n, r, p, klen)
}

func ctrCipher(data, key, iv []byte) ([]byte, error) {
	// AES encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}
