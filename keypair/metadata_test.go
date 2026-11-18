package keypair

import (
	"encoding/json"
	"testing"
)

func TestAuthenticatedMetadata(t *testing.T) {
	pri, _, err := GenerateKeyPair(PK_ECDSA, P256)
	if err != nil {
		t.Fatal(err)
	}
	p := &ScryptParam{N: 2, R: 1, P: 1, DKLen: 64}
	for _, password := range [][]byte{nil, {}} {
		if _, err := EncryptWithCustomScrypt(pri, "address", password, p); err == nil {
			t.Fatal("accepted empty password")
		}
	}
	key, err := EncryptWithCustomScrypt(pri, "address", []byte("password"), p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	var restored ProtectedKey
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecryptAuthenticatedPrivateKey(&restored, []byte("password"), p)
	if err != nil {
		t.Fatal(err)
	}
	if !ComparePublicKey(pri.Public(), decoded.Public()) {
		t.Fatal("wrong public key")
	}
	mutations := map[string]func(*ProtectedKey){
		"algorithm":     func(k *ProtectedKey) { k.Alg = "SM2" },
		"curve":         func(k *ProtectedKey) { k.Param["curve"] = "sm2p256v1" },
		"address":       func(k *ProtectedKey) { k.Address += "x" },
		"salt":          func(k *ProtectedKey) { k.Salt[0] ^= 1 },
		"hash":          func(k *ProtectedKey) { k.Hash = "changed" },
		"gcm downgrade": func(k *ProtectedKey) { k.EncAlg = "aes-256-gcm" },
		"ctr downgrade": func(k *ProtectedKey) { k.EncAlg = "aes-256-ctr" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed ProtectedKey
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if _, err := DecryptAuthenticatedPrivateKey(&changed, []byte("password"), p); err == nil {
				t.Fatal("accepted tampered metadata")
			}
		})
	}
}
