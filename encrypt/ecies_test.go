package encrypt

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ontio/ontology-crypto/keypair"
	"crypto"
)

var DefaultCurve = elliptic.P256()

// Verify that an encrypted message can be successfully decrypted.
func TestEncryptDecrypt(t *testing.T) {
	prv1, _, err := keypair.GenerateKeyPair(keypair.PK_ECIES, keypair.P256)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	prv2, pub2, err := keypair.GenerateKeyPair(keypair.PK_ECIES, keypair.P256)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(AES128withSHA256, pub2, message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	fmt.Println("Encrypt Message: ", hex.EncodeToString(ct))
	pt, err := Decrypt(prv2, ct, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(pt, message) {
		fmt.Println("ecies: plaintext doesn't match message")
		t.FailNow()
	}

	_, err = Decrypt(prv1, ct, nil, nil)
	if err == nil {
		fmt.Println("ecies: encryption should not have succeeded")
		t.FailNow()
	}
}

// Verify that an encrypted message can be successfully decrypted.
func TestEncryptDecryptX(t *testing.T) {
	prv1, pub1, err := keypair.GenerateKeyPair(keypair.PK_ECIES, keypair.P256)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	pk := keypair.SerializePublicKey(pub1)
	pkz, err := keypair.DeserializePublicKey(pk)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(AES128withSHA256, crypto.PublicKey(pkz), message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	fmt.Println("Encrypt Message: ", hex.EncodeToString(ct))
	pt, err := Decrypt(prv1, ct, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	if !bytes.Equal(pt, message) {
		fmt.Println("ecies: plaintext doesn't match message")
		t.FailNow()
	}
}



// Verify that an encrypted message can be successfully decrypted.
func TestEncryptDecryptXX(t *testing.T) {
	pk, err := hex.DecodeString("032a31b39bec02be337a7ab25dee5bcf44b3758c51611829526bca8fcf097ff8f5")
	pkz, err := keypair.DeserializePublicKey(pk)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	message := []byte("Hello, world.")
	ct, err := Encrypt(AES128withSHA256, crypto.PublicKey(pkz), message, nil, nil)
	if err != nil {
		fmt.Println(err.Error())
		t.FailNow()
	}

	fmt.Println("Encrypt Message: ", hex.EncodeToString(ct))

}