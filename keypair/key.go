// Package keypair implements asymmetric key pair generation and some related
// functions.
//
// Multiple types of key pair supported:
//     ECDSA
//     SM2
//
package keypair

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/OntologyNetwork/ont-crypto/ec"
)

type KeyType byte

// Supported key types
const (
	PK_ECDSA KeyType = 0x12
	PK_SM2           = 0x13
)

const err_generate = "key pair generation failed, "

// GenerateKeyPair generates a pair of private and public keys in type t.
// opts is the necessary parameter(s), which is defined by the key type:
//     ECDSA: a byte specifies the elliptic curve, which defined in package ec
//     SM2: same as ECDSA
//
func GenerateKeyPair(t KeyType, opts interface{}) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch t {
	case PK_ECDSA, PK_SM2:
		param, ok := opts.(byte)
		if !ok {
			return nil, nil, errors.New(err_generate + "invalid EC options, 1 byte curve label excepted")
		}
		c, err := ec.GetCurve(param)
		if err != nil {
			return nil, nil, errors.New(err_generate + err.Error())
		}

		if t == PK_ECDSA {
			return ec.GenerateECKeyPair(c, rand.Reader, ec.ECDSA)
		} else {
			return ec.GenerateECKeyPair(c, rand.Reader, ec.SM2)
		}

	default:
		return nil, nil, errors.New(err_generate + "unknown algorithm")
	}

}

// SerializePublicKey serializes the public key to a byte sequence.
func SerializePublicKey(key crypto.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			buf.WriteByte(byte(PK_ECDSA))
		case ec.SM2:
			buf.WriteByte(byte(PK_SM2))
		}
		label, err := ec.GetCurveLabel(t.Curve)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, true))
	default:
		panic("unknown public key type")
	}

	return buf.Bytes()
}

// DeserializePublicKey parse the byte sequencce to a public key.
func DeserializePublicKey(data []byte) (crypto.PublicKey, error) {
	switch KeyType(data[0]) {
	case PK_ECDSA, PK_SM2:
		c, err := ec.GetCurve(data[1])
		if err != nil {
			return nil, err
		}
		pub, err := ec.DecodePublicKey(data[2:], c)
		if err != nil {
			return nil, err
		}
		pk := &ec.PublicKey{
			Algorithm: ec.ECDSA,
			PublicKey: pub,
		}

		switch KeyType(data[0]) {
		case PK_ECDSA:
			pk.Algorithm = ec.ECDSA
		case PK_SM2:
			pk.Algorithm = ec.SM2
		default:
			return nil, errors.New("unknown EC algorithm")
		}

		return pk, nil

	default:
		return nil, errors.New("unrecognized algorithm label")
	}

}
