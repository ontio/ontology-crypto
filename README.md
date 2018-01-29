# ont-crypto

Cryptography Library for Ontology Network

# Usage

## Key pair

```go
import "github.com/OntologyNetwork/ont-crypto/keypair"
import "github.com/OntologyNetwork/ont-crypto/ec"

...

// Generate key pair
private, public, err := keypair.GenerateKeyPair(keypair.PK_ECDSA, ec.P256)

// Serialize public key
buf := keypair.SerializePublicKey(public)

// Deserialize public key
public, err := keypair.DeserializePublicKey(buf)
```

## Signature

```go
import "github.com/OntologyNetwork/ont-crypto/signature"

...

// Generate signature for @msg using private key @private
sig, err := signature.Sign(signature.SHA256WITHECDSA, private, msg, nil)

// Serialization
buf, err := signature.Serialize(sig)

// Deserialization
sig, err = Deserialize(buf)

// Verify the signature using public key @public
ok := Verify(public, msg, sig)
```
