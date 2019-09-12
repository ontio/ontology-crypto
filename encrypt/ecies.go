package encrypt

import (
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/ontio/ontology-crypto/ec"
	"reflect"
)

var (
	ErrImport                     = fmt.Errorf("ecies: failed to import key")
	ErrInvalidCurve               = fmt.Errorf("ecies: invalid elliptic curve")
	ErrInvalidParams              = fmt.Errorf("ecies: invalid ECIES parameters")
	ErrInvalidPublicKey           = fmt.Errorf("ecies: invalid public key")
	ErrSharedKeyIsPointAtInfinity = fmt.Errorf("ecies: shared key is point at infinity")
	ErrSharedKeyTooBig            = fmt.Errorf("ecies: shared key params are too big")
)

var (
	ErrKeyDataTooLong = fmt.Errorf("ecies: can't supply requested key data")
	ErrSharedTooLong  = fmt.Errorf("ecies: shared secret is too long")
	ErrInvalidMessage = fmt.Errorf("ecies: invalid message")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

// NIST SP 800-56 Concatenation Key Derivation Function (see section 5.8.1).
func concatKDF(hash hash.Hash, z, s1 []byte, kdLen int) (k []byte, err error) {
	if s1 == nil {
		s1 = make([]byte, 0)
	}

	reps := ((kdLen + 7) * 8) / (hash.BlockSize() * 8)
	if big.NewInt(int64(reps)).Cmp(big2To32M1) > 0 {
		fmt.Println(big2To32M1)
		return nil, ErrKeyDataTooLong
	}

	counter := []byte{0, 0, 0, 1}
	k = make([]byte, 0)

	for i := 0; i <= reps; i++ {
		hash.Write(counter)
		hash.Write(z)
		hash.Write(s1)
		k = append(k, hash.Sum(nil)...)
		hash.Reset()
		incCounter(counter)
	}

	k = k[:kdLen]
	return
}

// messageTag computes the MAC of a message (called the tag) as per
// SEC 1, 3.5.
func messageTag(hash func() hash.Hash, km, msg, shared []byte) []byte {
	if shared == nil {
		shared = make([]byte, 0)
	}
	mac := hmac.New(hash, km)
	mac.Write(msg)
	tag := mac.Sum(nil)
	return tag
}

// Generate an initialisation vector for CTR mode.
func generateIV(ecies EciesScheme, rand io.Reader) (iv []byte, err error) {
	blockSize := GetBlockSize(ecies)
	iv = make([]byte, blockSize)
	_, err = io.ReadFull(rand, iv)
	return
}

// symEncrypt carries out CTR encryption using the block cipher specified in the
// parameters.
func symEncrypt(ecies EciesScheme, key, m []byte) (ct []byte, err error) {
	cip := GetCipher(ecies)
	c, err := cip(key)
	if err != nil {
		return
	}

	iv, err := generateIV(ecies, rand.Reader)
	if err != nil {
		return
	}
	ctr := cipher.NewCTR(c, iv)

	blockSize := GetBlockSize(ecies)
	ct = make([]byte, len(m)+blockSize)
	copy(ct, iv)
	ctr.XORKeyStream(ct[blockSize:], m)
	return
}

// symDecrypt carries out CTR decryption using the block cipher specified in
// the parameters
func symDecrypt(ecies EciesScheme, key, ct []byte) (m []byte, err error) {
	cip := GetCipher(ecies)
	c, err := cip(key)
	if err != nil {
		return
	}
	blockSize := GetBlockSize(ecies)
	ctr := cipher.NewCTR(c, ct[:blockSize])

	m = make([]byte, len(ct)-blockSize)
	ctr.XORKeyStream(m, ct[blockSize:])
	return
}

// MaxSharedKeyLength returns the maximum length of the shared key the
// public key can produce.
func MaxSharedKeyLength(pub crypto.PublicKey) int {
	switch key := pub.(type) {
	case *ec.PublicKey:
		return (key.Curve.Params().BitSize + 7) / 8
	default:
		fmt.Println("Key type is not support")
	}
	return 0
}

func GenerateEcKey(c elliptic.Curve) (*ec.PrivateKey, error) {
	d, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	prv := &ec.PrivateKey{
		Algorithm: ec.ECIES,
		PrivateKey: &ecdsa.PrivateKey{
			D: new(big.Int).SetBytes(d),
			PublicKey: ecdsa.PublicKey{
				X:     x,
				Y:     y,
				Curve: c,
			},
		},
	}
	return prv, nil
}

// ECDH key agreement method used to establish secret keys for encryption.
func GenerateShared(prvKey crypto.PrivateKey, pubKey crypto.PublicKey, skLen, macLen int) (sk []byte, err error) {
	switch prv := prvKey.(type) {
	case *ec.PrivateKey:
		if pub, ok := pubKey.(*ec.PublicKey); ok {
			if prv.PublicKey.Curve != pub.Curve {
				return nil, ErrInvalidCurve
			}
			if skLen+macLen > MaxSharedKeyLength(pub) {
				return nil, ErrSharedKeyTooBig
			}
			x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, prv.D.Bytes())
			if x == nil {
				return nil, ErrSharedKeyIsPointAtInfinity
			}

			sk = make([]byte, skLen+macLen)
			skBytes := x.Bytes()
			copy(sk[len(sk)-len(skBytes):], skBytes)
			return sk, nil
		}
	}
	return nil, fmt.Errorf("GenerateShared Not support: %s", reflect.TypeOf(prvKey).String())
}

// Encrypt encrypts a message using ECIES as specified in SEC 1, 5.1. If
// the shared information parameters aren't being used, they should be
// nil.
func Encrypt(ecies EciesScheme, pubKey crypto.PublicKey, m, s1, s2 []byte) ([]byte, error) {
	var ct []byte
	hasher := GetHash(ecies)
	keyLen := GetKeyLen(ecies)
	blockSize := GetBlockSize(ecies)

	switch pub := pubKey.(type) {
	case *ec.PublicKey:
		R, err := GenerateEcKey(pub.Curve)
		if err != nil {
			return nil, err
		}

		hash := hasher()
		z, err := GenerateShared(R, pub, keyLen, keyLen)
		if err != nil {
			return nil, err
		}
		K, err := concatKDF(hash, z, s1, keyLen+keyLen)
		if err != nil {
			return nil, err
		}
		Ke := K[:keyLen]
		Km := K[keyLen:]

		hash.Write(Km)
		Km = hash.Sum(nil)
		hash.Reset()

		em, err := symEncrypt(ecies, Ke, m)
		if err != nil || len(em) <= blockSize {
			return nil, err
		}

		d := messageTag(hasher, Km, em, s2)

		Rb := elliptic.Marshal(pub.Curve, R.PublicKey.X, R.PublicKey.Y)
		ct = make([]byte, 1+len(Rb)+len(em)+len(d))
		ct[0] = byte(ecies)
		copy(ct[1:], Rb)
		copy(ct[1+len(Rb):], em)
		copy(ct[1+len(Rb)+len(em):], d)
		return ct, nil
	default:
		return nil, fmt.Errorf("Encrypt unsupport key type: %s", reflect.TypeOf(pubKey).String())
	}
}

// Decrypt decrypts an ECIES ciphertext.
func Decrypt(prvKey crypto.PrivateKey, c, s1, s2 []byte) ([]byte, error) {
	var m []byte
	if c == nil || len(c) == 0 {
		return nil, fmt.Errorf("Decrypt Parameter error")
	}
	ecies := EciesScheme(c[0])
	hasher := GetHash(ecies)
	keyLen := GetKeyLen(ecies)

	switch prv := prvKey.(type) {
	case *ec.PrivateKey:
		hash := hasher()

		var (
			rLen   int
			hLen   int = hash.Size()
			mStart int
			mEnd   int
		)

		switch c[1] {
		case 2, 3, 4:
			rLen = (prv.PublicKey.Curve.Params().BitSize + 7) / 4
			if len(c) < (rLen + hLen + 1 + 1) {
				return nil, fmt.Errorf("Decrypt encrypt message length error")
			}
		default:
			return nil, ErrInvalidPublicKey
		}

		mStart = rLen + 1
		mEnd = len(c) - hLen

		R := &ec.PublicKey{
			PublicKey: &ecdsa.PublicKey{
				Curve: prv.PublicKey.Curve,
			},
		}
		R.PublicKey.X, R.PublicKey.Y = elliptic.Unmarshal(R.PublicKey.Curve, c[1:rLen+1])
		if R.X == nil {
			return nil, ErrInvalidPublicKey
		}

		z, err := GenerateShared(prv, R, keyLen, keyLen)
		if err != nil {
			return nil, err
		}

		K, err := concatKDF(hash, z, s1, keyLen+keyLen)
		if err != nil {
			return nil, err
		}

		Ke := K[:keyLen]
		Km := K[keyLen:]
		hash.Write(Km)
		Km = hash.Sum(nil)
		hash.Reset()

		d := messageTag(hasher, Km, c[mStart:mEnd], s2)
		if subtle.ConstantTimeCompare(c[mEnd:], d) != 1 {
			return nil, ErrInvalidMessage
		}

		m, err = symDecrypt(ecies, Ke, c[mStart:mEnd])
		return m, nil
	default:
		return nil, fmt.Errorf("Decrypt unsupport key type: %s", reflect.TypeOf(prvKey).String())
	}
}
