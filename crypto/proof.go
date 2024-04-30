package crypto

import (
	"bytes"
	"encoding/json"
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

var _ = json.Marshaler(&ProofSignature{})
var _ = json.Unmarshaler(&ProofSignature{})

func (p *ProofSignature) MarshalJSON() ([]byte, error) {
	b := []byte{}

	g, _ := p.Gamma.MarshalBinary()
	b = append(b, g...)
	b = append(b, '$')
	c, _ := p.C.MarshalBinary()
	b = append(b, c...)
	b = append(b, '$')
	b = append(b, p.S...)
	b = append(b, '$')
	b = append(b, p.Delta...)
	b = append(b, '$')
	b = append(b, p.Theta...)

	return b, nil
}

func (p *ProofSignature) UnmarshalJSON(b []byte) error {

	bs := bytes.Split(b, []byte{'&'})
	p.Gamma.UnmarshalBinary(bs[0])
	p.C.UnmarshalBinary(bs[1])
	p.S = bs[2]
	p.Delta = bs[3]
	p.Delta = bs[4]
	return nil
}
