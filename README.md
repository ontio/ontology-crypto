# Ontology Crypto

Cryptography Library for Ontology Network

# Usage
## Key pair

```go
import "github.com/ontio/ontology-crypto/keypair"

...

// Generate key pair
private, public, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, keypair.P256)

// Serialize public key
buf := keypair.SerializePublicKey(public)

// Deserialize public key
public, err := keypair.DeserializePublicKey(buf)
```

## Signature

```go
import "github.com/ontio/ontology-crypto/signature"

...

// Generate signature for @msg using private key @private
sig, err := signature.Sign(signature.SHA256withECDSA, private, msg, nil)

// Serialization
buf, err := signature.Serialize(sig)

// Deserialization
sig, err = signature.Deserialize(buf)

// Verify the signature using public key @public
ok := signature.Verify(public, msg, sig)
```
