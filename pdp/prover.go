package pdp

import (
	"crypto/sha256"
	"math/big"

	"github.com/ontio/ontology-crypto/ate-bn256"
)

/**
Description: 存储节点根据可验证随机函数
Params:
	challenge: 	根据块索引集合，随机生成的数据集合
	tags:		随机选取的数据块的认证元数据集合
	blocks:		随机选取的数据块集合
Returns:
	return1:	通过累乘运算出来的证明验证元素
	return2:	通过累加运算出来的证明验证元素
*/

func ProofGenerate(challenge []Challenge, byteTags []Element, blocks []Block) ([]byte, string) {
	if len(byteTags) != len(challenge) || len(byteTags) != len(blocks) {
	}

	var tags []*bn256.G1
	for _, tag := range byteTags {
		tmp, _ := new(bn256.G1).Unmarshal(tag.Buffer)
		tags = append(tags, tmp)
	}

	block0 := sha256.Sum256(blocks[0].Buffer)
	addRes := new(big.Int).Mul(new(big.Int).SetUint64(uint64(challenge[0].Rand)), new(big.Int).SetBytes(block0[:]))
	multiRes := new(bn256.G1).ScalarMult(tags[0], new(big.Int).SetUint64(uint64(challenge[0].Rand)))
	for i := 1; i < len(challenge); i++ {
		tmp1 := new(bn256.G1).ScalarMult(tags[i], new(big.Int).SetUint64(uint64(challenge[i].Rand)))
		multiRes = new(bn256.G1).Add(multiRes, tmp1)
		_block := sha256.Sum256(blocks[i].Buffer)
		addRes = new(big.Int).Add(addRes, new(big.Int).Mul(new(big.Int).SetUint64(uint64(challenge[i].Rand)), new(big.Int).SetBytes(_block[:])))
	}
	return multiRes.Marshal(), addRes.String()
}
