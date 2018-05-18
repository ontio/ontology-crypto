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
	"crypto/sha256"

	"github.com/ontio/ontology-crypto/ec"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
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

var (
	// parameters used in scrypt
	n    = DEFAULT_N
	r    = DEFAULT_R
	p    = DEFAULT_P
	klen = DEFAULT_DERIVED_KEY_LENGTH
)

// Encrypt the private key with the given password.
// The password is used to derive a key via scrypt function.
// AES with CTR mode is used for encryption. The first 16 bytes of the derived
// key is used as the initial vector (IV), and the last 32 bytes is used as the
// encryption key.
func EncryptPrivateKey(pri PrivateKey, addr string, pwd []byte) (*ProtectedKey, error) {
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
func DecryptPrivateKey(prot *ProtectedKey, pwd []byte) (PrivateKey, error) {
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

// Re-encrypt the private key with the new password and scrypt parameters.
// The old password and scrypt parameters are used for decryption first.
// The scrypt parameters will be reseted to the default after this function.
func ReencryptPrivateKey(prot *ProtectedKey, oldPwd, newPwd []byte, oldParam, newParam *ScryptParam) (*ProtectedKey, error) {
	SetScryptParam(oldParam)
	pri, err := DecryptPrivateKey(prot, oldPwd)
	if err != nil {
		return nil, err
	}
	SetScryptParam(newParam)
	newProt, err := EncryptPrivateKey(pri, prot.Address, newPwd)
	SetScryptParam(nil)
	return newProt, err
}

// Set the scrypt parameters.
// This will change the global environments and effect following
// encryption/decryption operations.
func SetScryptParam(param *ScryptParam) {
	if param == nil {
		n = DEFAULT_N
		p = DEFAULT_R
		r = DEFAULT_P
		klen = DEFAULT_DERIVED_KEY_LENGTH
	} else {
		n = param.N
		p = param.P
		r = param.R
		klen = param.DKLen
	}
}

func kdf(addr string, pwd []byte) ([]byte, error) {
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

// Return the parameters used in scrypt function
func GetScryptParameters() *ScryptParam {
	return &ScryptParam{N: n, R: r, P: p, DKLen: klen}
}
