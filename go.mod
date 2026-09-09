module github.com/ontio/ontology-crypto

go 1.12

require (
	github.com/btcsuite/btcd v0.23.3
	github.com/btcsuite/btcd/btcec/v2 v2.1.3
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce // indirect
	github.com/ethereum/go-ethereum v1.9.25
	github.com/itchyny/base58-go v0.1.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/tools v0.1.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace golang.org/x/crypto => github.com/golang/crypto v0.0.0-20191029031824-8986dd9e96cf
