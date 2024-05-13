package crypto

import (
	"bytes"
	paillier "github.com/ColdFaceMagicMan/go-go-gadget-paillier"
	"go.dedis.ch/kyber/v3"
	"math/big"
)

/*
实验平台
函数分开测

变量

图表

1 背景 研究现状 现有技术问题 我们方法动机 实施过程 行文结构
2 vrf、 algo、混淆、抽象代数数据结构
3 本文算法方案设计 描述vrf算法、algovrf流程、结合的流程、流程图
4 正确性分析 复杂度 input、output size
5 实验结果 设置、平台、参数 结果分析
6 结论参考第一章 展望不足、优化性能
7 谢词

使用其他文章内容要标引用
别人git仓库标注


*/

// TODO: Go arrays are copied by value, so any call to e.g. VrfPrivkey.Prove() makes a copy of the secret key that lingers in memory.
// To avoid this, should we instead allocate memory for secret keys here (maybe even in the C heap) and pass around pointers?
// e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?
type (
	// A VrfPrivkey is a private key used for producing VRF proofs.
	// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
	VrfPrivkey [645]byte
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey [160]byte
	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof [192]byte
	// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
	// The VRF scheme guarantees that such output will be unique
	VrfOutput [32]byte
)

type PrivKeys struct {
	ProofDecKey *paillier.PrivateKey
	VrfKey      kyber.Scalar
}

type PubKeys struct {
	ProofEncKey *paillier.PublicKey
	VrfKey      kyber.Point
}

var bigIntOne = new(big.Int).SetInt64(1)

func (p *PubKeys) MarshalBinary() (data VrfPubkey, err error) {
	buf := bytes.Buffer{}
	pk := make([]byte, 128)
	buf.Write(p.ProofEncKey.N.FillBytes(pk))
	vk, _ := p.VrfKey.MarshalBinary()
	buf.Write(vk)
	copy(data[:], buf.Bytes())
	return
}

func (p *PubKeys) UnmarshalBinary(data VrfPubkey) error {
	n := new(big.Int).SetBytes(data[:128])
	p.ProofEncKey = &paillier.PublicKey{
		N:        n,
		G:        new(big.Int).Add(n, bigIntOne),
		NSquared: new(big.Int).Mul(n, n),
	}
	p.VrfKey = GetPP().Point()
	p.VrfKey.UnmarshalBinary(data[128:])
	return nil
}

func (p *PrivKeys) MarshalBinary() (data VrfPrivkey, err error) {
	sk := *p.ProofDecKey
	buf := bytes.Buffer{}

	vk, _ := p.VrfKey.MarshalBinary()
	buf.Write(vk)
	skB := sk.MarshalBinary()
	buf.Write(skB)

	copy(data[:], buf.Bytes())

	return
}

func (p *PrivKeys) UnmarshalBinary(data VrfPrivkey) error {
	p.VrfKey = GetPP().Scalar()
	p.VrfKey.UnmarshalBinary(data[:32])

	decKey := &paillier.PrivateKey{}
	decKey.UnmarshalBinary(data[32:])
	p.ProofDecKey = decKey
	return nil
}
