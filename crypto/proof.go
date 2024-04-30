package crypto

import (
	"bytes"
	"go.dedis.ch/kyber/v3"
)

// Signature represents a cryptographic signature.
type ProofSignature struct {
	Gamma kyber.Point
	C     kyber.Scalar
	S     []byte
	Delta []byte
	Theta []byte
}

func (p *ProofSignature) MarshalJSON() (proof VrfProof, err error) {
	buf := bytes.Buffer{}

	g, _ := p.Gamma.MarshalBinary()
	buf.Write(g)

	c, _ := p.C.MarshalBinary()
	buf.Write(c)

	buf.Write(p.S)
	buf.Write(p.Delta)
	buf.Write(p.Theta)

	copy(proof[:], buf.Bytes())

	return
}

func (p *ProofSignature) UnmarshalJSON(proofBytes VrfProof) error {
	data := proofBytes[:]

	p.Gamma = GetPP().Point()
	p.Gamma.UnmarshalBinary(data[:32])
	data = data[32:]
	p.C = GetPP().Scalar()
	p.C.UnmarshalBinary(data[:32])
	data = data[32:]

	if len(data) < 256 {
		p.S = data[:32]
		data = data[32:]
		p.Delta = data[:32]
		data = data[32:]
		p.Theta = data[:64]
	} else {
		p.S = data[:256]
		data = data[256:]
		p.Delta = data[:256]
		data = data[256:]
		p.Theta = data[:256]
	}

	return nil
}
