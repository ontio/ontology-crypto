package signature

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/OntologyNetwork/ont-crypto/ec"
	"github.com/OntologyNetwork/ont-crypto/sm2"
)

type Signature struct {
	Scheme SignatureScheme
	Value  interface{}
}

type DSASignature struct {
	R, S *big.Int
}

type SM2Signature struct {
	DSASignature
	ID string
}

func Sign(scheme SignatureScheme, pri crypto.PrivateKey, msg []byte, opt interface{}) (*Signature, error) {
	hasher := GetHash(scheme)
	if hasher == nil {
		return nil, errors.New("unknown signature scheme")
	}

	var res Signature
	res.Scheme = scheme
	switch key := pri.(type) {
	case *ec.PrivateKey:
		if scheme == SM3withSM2 {
			id := ""
			if opt, ok := opt.(string); ok {
				id = opt
			}
			r, s, err := sm2.Sign(rand.Reader, key.PrivateKey, id, msg, hasher)
			if err != nil {
				return nil, err
			}
			res.Value = &SM2Signature{
				ID:           id,
				DSASignature: DSASignature{R: r, S: s},
			}
		} else if scheme == SHA256withECDSA ||
			scheme == SHA512withECDSA {
			digest := hasher.Sum(msg)
			r, s, err := ecdsa.Sign(rand.Reader, key.PrivateKey, digest)
			if err != nil {
				return nil, err
			}
			res.Value = &DSASignature{R: r, S: s}
		} else {
			return nil, errors.New("unmatched signature algorithm and private key")
		}

	default:
		return nil, errors.New("unknown type of private key")
	}

	return &res, nil
}

func Verify(pub crypto.PublicKey, msg []byte, sig *Signature) (bool, error) {
	if len(msg) == 0 {
		return false, errors.New("invalid argument: empty message")
	}

	if sig == nil {
		return false, errors.New("invalid argument: signature is nil")
	}

	h := GetHash(sig.Scheme)
	if h == nil {
		return false, errors.New("unknown signature scheme")
	}

	res := true

	switch key := pub.(type) {
	case *ec.PublicKey:
		switch sig.Scheme {
		case SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, RIPEMD160withECDSA:
			if v, ok := sig.Value.(*DSASignature); ok {
				digest := h.Sum(msg)
				res = ecdsa.Verify(key.PublicKey, digest, v.R, v.S)
			} else {
				return false, errors.New("invalid signature value")
			}
		case SM3withSM2:
			if v, ok := sig.Value.(*SM2Signature); ok {
				res = sm2.Verify(key.PublicKey, v.ID, msg, h, v.R, v.S)
			} else {
				return false, errors.New("invalid signature value")
			}
		default:
			return false, errors.New("unsupported signature scheme")
		}

	default:
		return false, errors.New("unsupported public key")
	}

	if !res {
		return false, errors.New("verification failed")
	}

	return true, nil
}

func Serialize(sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("failed serializing signature: input is nil")
	}

	var buf bytes.Buffer
	switch v := sig.Value.(type) {
	case *DSASignature:
		if sig.Scheme != SHA224withECDSA ||
			sig.Scheme != SHA256withECDSA ||
			sig.Scheme != SHA384withECDSA ||
			sig.Scheme != SHA512withECDSA ||
			sig.Scheme != RIPEMD160withECDSA {
			return nil, errors.New("failed serializing signature: unmatched signature scheme and value")
		}

		buf.WriteByte(byte(sig.Scheme))
		serializeDSA(v, &buf)
	case *SM2Signature:
		if sig.Scheme != SM3withSM2 {
			return nil, errors.New("failed serializing signature: unmatched signature scheme and value")
		}
		buf.WriteByte(byte(sig.Scheme))
		buf.Write([]byte(v.ID))
		buf.WriteByte(byte(0))
		serializeDSA(&v.DSASignature, &buf)
	default:
		return nil, errors.New("failed serializing signature: unrecognized signature type")
	}

	return buf.Bytes(), nil
}

func Deserialize(buf []byte) (*Signature, error) {
	e := "failed deserializing signature: "
	if buf == nil || len(buf) < 2 {
		return nil, errors.New(e + "invalid argument")
	}

	var sig Signature
	sig.Scheme = SignatureScheme(buf[0])
	switch sig.Scheme {
	case SHA224withECDSA, SHA256withECDSA, SHA384withECDSA, SHA512withECDSA, RIPEMD160withECDSA:
		dsa, err := deserializeDSA(buf[1:])
		if err != nil {
			return nil, errors.New(e + err.Error())
		}
		sig.Value = dsa
	case SM3withSM2:
		i := 1
		for i < len(buf) && buf[i] != 0 {
			i++
		}
		if i >= len(buf) {
			return nil, errors.New(e + "invalid format")
		}
		id := string(buf[1:i])
		dsa, err := deserializeDSA(buf[i+1:])
		if err != nil {
			return nil, errors.New(e + err.Error())
		}
		sig.Value = &SM2Signature{ID: id, DSASignature: *dsa}
	default:
		return nil, errors.New(e + "unknown signature scheme")
	}
	return &sig, nil
}

func serializeDSA(sig *DSASignature, w io.Writer) {
	if sig == nil || sig.R == nil || sig.S == nil {
		panic("serializeDSA: invalid argument")
	}

	r := sig.R.Bytes()
	s := sig.S.Bytes()
	lr := len(r)
	ls := len(s)
	if lr < ls {
		w.Write(make([]byte, ls-lr))
	}
	w.Write(r)
	if ls < lr {
		w.Write(make([]byte, lr-ls))
	}
	w.Write(s)
}

func deserializeDSA(buf []byte) (*DSASignature, error) {
	if buf == nil {
		panic("deserializeDSA: invalid argument")
	}

	length := len(buf)
	if length&1 != 0 {
		return nil, errors.New("invalid length")
	}

	return &DSASignature{
		R: new(big.Int).SetBytes(buf[0 : length/2]),
		S: new(big.Int).SetBytes(buf[length/2:]),
	}, nil
}
