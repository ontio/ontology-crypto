module github.com/ontio/ontology-crypto

go 1.12

require (
	github.com/btcsuite/btcd v0.22.0-beta
	github.com/ethereum/go-ethereum v1.10.22
	github.com/itchyny/base58-go v0.1.0
	github.com/stretchr/testify v1.7.2
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
)

replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20191029031824-8986dd9e96cf
