/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

package keypair

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/ontio/ontology-crypto/ec"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

// ProtectedKey stores the encrypted private key and related data
type ProtectedKey struct {
	Address string            `json:"address"`
	EncAlg  string            `json:"enc-alg"`
	Key     []byte            `json:"key"`
	Alg     string            `json:"algorithm"`
	Salt    []byte            `json:"salt,omitempty"`
	Hash    string            `json:"hash,omitempty"`
	Param   map[string]string `json:"parameters,omitempty"`
}

// ScryptParam contains the parameters used in scrypt function
type ScryptParam struct {
	P     int `json:"p"`
	N     int `json:"n"`
	R     int `json:"r"`
	DKLen int `json:"dkLen,omitempty"`
}

const (
	DEFAULT_N                  = 16384
	DEFAULT_R                  = 8
	DEFAULT_P                  = 8
	DEFAULT_DERIVED_KEY_LENGTH = 64
)

// Encrypt the private key with the given password. The password is used to
// derive a key via scrypt function. AES with GCM mode is used for encryption.
// The first 12 bytes of the derived key is used as the nonce, and the last 32
// bytes is used as the encryption key.
func EncryptPrivateKey(pri PrivateKey, addr string, pwd []byte) (*ProtectedKey, error) {
	return EncryptWithCustomScrypt(pri, addr, pwd, GetScryptParameters())
}

// Decrypt the private key using the given password
func DecryptPrivateKey(prot *ProtectedKey, pwd []byte) (PrivateKey, error) {
	return DecryptWithCustomScrypt(prot, pwd, GetScryptParameters())
}

func EncryptWithCustomScrypt(pri PrivateKey, addr string, pwd []byte, param *ScryptParam) (*ProtectedKey, error) {
	if len(pwd) == 0 {
		return nil, NewEncryptError("empty password")
	}
	var res = ProtectedKey{
		Address: addr,
		EncAlg:  "aes-256-gcm-v2",
	}

	salt, err := randomBytes(16)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}
	res.Salt = salt

	dkey, err := kdf(pwd, salt, param)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}
	nonce := dkey[:12]
	ekey := dkey[len(dkey)-32:]

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

	gcm, err := gcmCipher(ekey)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}

	aad, err := protectedKeyAAD(&res)
	if err != nil {
		return nil, NewEncryptError(err.Error())
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	res.Key = ciphertext
	return &res, nil
}

func DecryptWithCustomScrypt(prot *ProtectedKey, pwd []byte, param *ScryptParam) (PrivateKey, error) {
	if prot == nil || len(pwd) == 0 {
		return nil, NewDecryptError("invalid argument")
	}

	var plaintext []byte

	// Check parameters
	switch prot.EncAlg {
	case "aes-256-gcm", "aes-256-gcm-v2":
		// generate random salt
		salt := prot.Salt
		dkey, err := kdf(pwd, salt, param)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		ekey := dkey[len(dkey)-32:]
		nonce := dkey[:12]
		gcm, err := gcmCipher(ekey)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		aad, err := protectedKeyAAD(prot)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		plaintext, err = gcm.Open(nil, nonce, prot.Key, aad)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
	case "aes-256-ctr":
		// Legacy format kept only for old accounts.
		//
		// AES-CTR provides confidentiality but no integrity: the ciphertext
		// can be flipped bit by bit without detection, and the derived key /
		// IV come from a deterministic salt derived from the address. New
		// accounts must use the "aes-256-gcm" format above. Migrate old keys
		// by decrypting and re-encrypting with EncryptWithCustomScrypt; do not
		// change the on-disk format in place.

		// generate salt from the address
		salt := saltFromAddress(prot.Address)
		// derive key
		dkey, err := kdf(pwd, salt, param)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		iv := dkey[:16]
		ekey := dkey[len(dkey)-32:]
		// Decryption, same process as encryption
		plaintext, err = ctrCipher(prot.Key, ekey, iv)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
	default:
		return nil, NewDecryptError("unsupported encryption algorithm")
	}

	switch prot.Alg {
	case "ECDSA", "SM2":
		curve, err := GetNamedCurve(prot.Param["curve"])
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		dkey, err := ec.ConstructPrivateKey(plaintext, curve)
		if err != nil {
			return nil, NewDecryptError(err.Error())
		}
		pri := ec.PrivateKey{PrivateKey: dkey}
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

// Re-encrypt the private key with the new password and scrypt parameters.
// The old password and scrypt parameters are used for decryption first.
// The scrypt parameters will be reseted to the default after this function.
func ReencryptPrivateKey(prot *ProtectedKey, oldPwd, newPwd []byte, oldParam, newParam *ScryptParam) (*ProtectedKey, error) {
	pri, err := DecryptWithCustomScrypt(prot, oldPwd, oldParam)
	if err != nil {
		return nil, err
	}
	newProt, err := EncryptWithCustomScrypt(pri, prot.Address, newPwd, newParam)
	return newProt, err
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func saltFromAddress(addr string) []byte {
	// Hash the address twice to get the salt
	digest := sha256.Sum256([]byte(addr))
	digest = sha256.Sum256(digest[:])
	return digest[:4]
}

func kdf(pwd []byte, salt []byte, param *ScryptParam) (dkey []byte, err error) {
	if param == nil || param.DKLen < 32 || param.DKLen > 1<<20 ||
		param.N < 2 || param.N&(param.N-1) != 0 || param.R <= 0 || param.P <= 0 {
		err = errors.New("invalid scrypt parameters")
		return
	}
	// Bound memory (128*r*(N+p+2)) and work (N*r*p). Divide before
	// multiplying so even attacker-controlled machine-sized integers are safe.
	const memoryUnits = 256 * 1024 * 1024 / 128
	const maxWork = 16 * 1024 * 1024
	if param.R > memoryUnits || param.N > memoryUnits/param.R {
		err = errors.New("scrypt resource limit exceeded")
		return
	}
	// At this point N <= memoryUnits/R, so the remaining budget for P is
	// non-negative. Split into two steps to keep all comparisons positive.
	remaining := memoryUnits/param.R - param.N
	if remaining < 2 || param.P > remaining-2 ||
		param.N > maxWork/param.R/param.P {
		err = errors.New("scrypt resource limit exceeded")
		return
	}

	// Derive the encryption key
	dkey, err = scrypt.Key([]byte(pwd), salt, param.N, param.R, param.P, param.DKLen)
	return
}

// protectedKeyAAD binds v2 ciphertext to its interpretation. JSON provides
// unambiguous field boundaries and deterministic ordering of string map keys.
func protectedKeyAAD(prot *ProtectedKey) ([]byte, error) {
	if prot.EncAlg == "aes-256-gcm" {
		return []byte(prot.Address), nil
	}
	data, err := json.Marshal(struct {
		Domain     string
		Address    string
		Algorithm  string
		Parameters map[string]string
		Salt       []byte
		Hash       string
	}{prot.EncAlg, prot.Address, prot.Alg, prot.Param, prot.Salt, prot.Hash})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// DecryptAuthenticatedPrivateKey rejects legacy formats whose metadata is not
// authenticated. Use this entry point for untrusted key files. Legacy imports
// must be explicitly opted into through DecryptWithCustomScrypt and re-encrypted.
func DecryptAuthenticatedPrivateKey(prot *ProtectedKey, pwd []byte, param *ScryptParam) (PrivateKey, error) {
	if prot == nil || prot.EncAlg != "aes-256-gcm-v2" {
		return nil, NewDecryptError("authenticated v2 key format required")
	}
	return DecryptWithCustomScrypt(prot, pwd, param)
}

func gcmCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm, nil
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

// Return the default parameters used in scrypt function
func GetScryptParameters() *ScryptParam {
	return &ScryptParam{
		N:     DEFAULT_N,
		R:     DEFAULT_R,
		P:     DEFAULT_P,
		DKLen: DEFAULT_DERIVED_KEY_LENGTH,
	}
}
