package pdp

import (
	"math/big"

	"github.com/ontio/ontology-crypto/ate-bn256"
)

/**
Description: 验证存储证明的的有效性
Params:
	g:			从存储合约读取的椭圆曲线基点
	g0：			从存储合约读取的文件相关的随机辅助变量
	fid:		从存储合约读取的文件相关的唯一文件表示
	pubKey:		从存储合约读取的文件存储所需的公钥

	multiRes:	存储节点通过累乘生成的存储证明元素
	addRes:		存储节点通过累加生成的存储证明元素

	challenge:	通过可验证随机算法选取的文件块索引和随机值集合
Returns:
	return1: 验证结果，成功返回true；失败返回false;
*/
func Verify(gStr, g0Str, pubKeyStr, multiResStr []byte, addResStr string, fid []byte, challenge []Challenge) bool {
	g, res := new(bn256.G2).Unmarshal(gStr)
	if res != nil {
		return false
	}
	g0, res := new(bn256.G1).Unmarshal(g0Str)
	if res != nil {
		return false
	}
	pubKey, res := new(bn256.G2).Unmarshal(pubKeyStr)
	if res != nil {
		return false
	}

	multiRes, res := new(bn256.G1).Unmarshal(multiResStr)
	if res != nil {
	}
	addRes, ret := new(big.Int).SetString(addResStr, 10)
	if ret != true {
		return false
	}

	hash0 := blsHash(g0, fid, int(challenge[0].Index))
	mMulti := new(bn256.G1).ScalarMult(hash0, new(big.Int).SetUint64(uint64(challenge[0].Rand)))

	for i := 1; i < len(challenge); i++ {
		_hash := blsHash(g0, fid, int(challenge[i].Index))
		mMulti = new(bn256.G1).Add(mMulti, new(bn256.G1).ScalarMult(_hash, new(big.Int).SetUint64(uint64(challenge[i].Rand))))
	}

	uPow := new(bn256.G1).ScalarMult(g0, addRes)

	lResult := bn256.Pair(multiRes, g)
	rResult := bn256.Pair(new(bn256.G1).Add(mMulti, uPow), pubKey)
	if lResult.String() == rResult.String() {
		return true
	} else {
		return false
	}
}
