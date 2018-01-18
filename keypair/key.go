// General public key serialization for multiple algorithms

package keypair

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"

	"github.com/OntologyNetwork/ont-crypto/ec"
)

const (
	// public key algorithm label
	PK_ECDSA = 0x12
	PK_SM2   = 0x13
)

const err_generate = "key pair generation failed, "

func GenerateKeyPair(alg byte, opts interface{}) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch alg {
	case PK_ECDSA, PK_SM2:
		t, ok := opts.(byte)
		if !ok {
			return nil, nil, errors.New(err_generate + "invalid EC options, 1 byte curve label excepted")
		}
		c, err := ec.GetCurve(t)
		if err != nil {
			return nil, nil, errors.New(err_generate + err.Error())
		}

		if alg == PK_ECDSA {
			return ec.GenerateECKeyPair(c, rand.Reader, ec.ECDSA)
		} else {
			return ec.GenerateECKeyPair(c, rand.Reader, ec.SM2)
		}

	default:
		return nil, nil, errors.New(err_generate + "unknown algorithm")
	}

}

// Serialize the public key as the following format:
//     algorithm label + parameters + public key
func SerializePublicKey(key crypto.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			buf.WriteByte(PK_ECDSA)
		case ec.SM2:
			buf.WriteByte(PK_SM2)
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

// Parse the public key from the buffer.
func DeserializePublicKey(data []byte) (crypto.PublicKey, error) {
	switch data[0] {
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

		switch data[0] {
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
