package crypto

import (
	"fmt"
	paillier "github.com/ColdFaceMagicMan/go-go-gadget-paillier"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/sign/schnorr"
)

// Suite defines the cryptographic suite interface.
type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
}

var pp *edwards25519.SuiteEd25519

func init() {
	pp = edwards25519.NewBlakeSHA256Ed25519()
}

func GetPP() Suite {
	if pp == nil {
		pp = edwards25519.NewBlakeSHA256Ed25519()
	}
	return pp
}

// hash1 computes the hash of a message using the provided cryptographic suite.
func hash1(suite Suite, message []byte) kyber.Point {
	c := suite.XOF([]byte("hash1"))
	c.Write(message)
	scalar := suite.Scalar().Pick(c)
	point := suite.Point().Mul(scalar, nil)
	return point
}

// hash2 computes the hash of a point using the provided cryptographic suite.
func hash2(suite Suite, in kyber.Point) []byte {
	hash2Length := 32
	pb, _ := in.MarshalBinary()
	c := suite.XOF([]byte("hash2"))
	c.Write(pb)
	scalar := suite.Scalar().Pick(c)
	point := suite.Point().Mul(scalar, nil)
	pointb, _ := point.MarshalBinary()
	return pointb[:hash2Length]
}

// hash3 computes the hash of multiple points using the provided cryptographic suite.
func hash3(suite Suite, points ...kyber.Point) kyber.Scalar {
	message := make([]byte, 0)
	for _, p := range points {
		pb, _ := p.MarshalBinary()
		message = append(message, pb...)
	}
	hash := suite.XOF([]byte("hash3"))
	hash.Write(message)
	c := suite.Scalar().Pick(hash)
	return c
}

// hash4 computes the hash of a scalar using the provided cryptographic suite.
func hash4(suite Suite, x kyber.Scalar) kyber.Scalar {
	pb, _ := x.MarshalBinary()
	c := suite.XOF([]byte("hash4"))
	c.Write(pb)
	scalar := suite.Scalar().Pick(c)
	return scalar
}

// RandGen generates a random signature for a given message using the provided cryptographic suite.
func RandGen(suite Suite, m []byte, pr VrfPrivkey, v kyber.Point, publicKey *paillier.PublicKey) ([]byte, *ProofSignature) {
	prvKry := PrivKeys{}
	prvKry.UnmarshalBinary(pr)
	x := prvKry.VrfKey
	x = suite.Scalar().Pick(suite.XOF([]byte("x")))

	h := hash1(suite, m)
	delta := hash4(suite, x)
	x0 := suite.Scalar().Mul(x, delta)
	delta0 := suite.Point().Mul(x0, nil)
	gamma := suite.Point().Mul(x0, h)
	k := suite.Scalar().Pick(suite.XOF([]byte("k")))

	g2 := suite.Point().Base()
	g2k := suite.Point().Mul(k, g2)
	hk := suite.Point().Mul(k, h)
	c := hash3(suite, g2, h, v, gamma, g2k, hk)
	s := suite.Scalar().Add(suite.Scalar().Mul(c, x0), k)

	signSuite := edwards25519.NewBlakeSHA256Ed25519()
	delta0b, _ := delta0.MarshalBinary()
	theta, _ := schnorr.Sign(signSuite, x, delta0b)

	y := hash2(suite, gamma)

	sb, _ := s.MarshalBinary()

	sBar, err := paillier.Encrypt(publicKey, sb)
	deltaBar, err := paillier.Encrypt(publicKey, delta0b)
	thetaBar, err := paillier.Encrypt(publicKey, theta)

	if err != nil {
		fmt.Println(err)
	}
	//th, _ := paillier.Decrypt(pr.ProofDecKey, thetaBar)
	//if len(th) != 64 {
	//	fmt.Println(theta[:8])
	//	fmt.Println(th[:8])
	//}

	return y, &ProofSignature{
		Gamma: gamma,
		C:     c,
		S:     sBar,
		Delta: deltaBar,
		Theta: thetaBar,
	}
}

// ProofDec decrypts a signature using the provided private key.
func ProofDec(piBar *ProofSignature, privKey *paillier.PrivateKey) *ProofSignature {
	s, _ := paillier.Decrypt(privKey, piBar.S)
	delta0, _ := paillier.Decrypt(privKey, piBar.Delta)
	thetaBar, _ := paillier.Decrypt(privKey, piBar.Theta)
	if len(thetaBar) == 63 {
		thetaBar = append([]uint8{0}, thetaBar...)
	}
	if len(s) != 32 {
		s = append([]uint8{0}, s...)
	}
	if len(delta0) != 32 {
		s = append([]uint8{0}, delta0...)
	}

	return &ProofSignature{
		Gamma: piBar.Gamma,
		C:     piBar.C,
		S:     s,
		Delta: delta0,
		Theta: thetaBar,
	}
}

// Verify checks the validity of a signature.
func Verify(suite Suite, v kyber.Point, m []byte, pi *ProofSignature) (ok bool, outPut VrfOutput) {
	gamma := pi.Gamma
	c := pi.C
	s := suite.Scalar()
	s.UnmarshalBinary(pi.S)
	delta0 := suite.Point()
	delta0.UnmarshalBinary(pi.Delta)
	theta := pi.Theta

	delta0c := suite.Point().Mul(c, suite.Point().Neg(delta0))
	g2S := suite.Point().Mul(s, nil)
	d1 := suite.Point().Add(delta0c, g2S)
	h := hash1(suite, m)
	gammac := suite.Point().Mul(c, suite.Point().Neg(gamma))
	hS := suite.Point().Mul(s, h)
	d2 := suite.Point().Add(gammac, hS)

	//signSuite := edwards25519.NewBlakeSHA256Ed25519()
	delta0b, _ := delta0.MarshalBinary()
	verifyResult := schnorr.Verify(GetPP(), v, delta0b, theta)

	g2 := suite.Point().Base()
	d3 := hash3(suite, g2, h, v, gamma, d1, d2)
	yCalc := hash2(suite, gamma)

	result := true
	if verifyResult != nil {
		result = false
		fmt.Println("sign: verification failed")
	}

	if !d3.Equal(c) {
		result = false
		fmt.Println("d3 is not equal to c")
	}

	copy(outPut[:], yCalc)

	return result, outPut
}

// Obf generates an obfuscated signature for a given message using the provided cryptographic suite.
func Obf(suite Suite, m []byte, x kyber.Scalar, v kyber.Point, publicKey *paillier.PublicKey) ([]byte, *ProofSignature) {
	delta := hash4(suite, x)
	x0 := suite.Scalar().Mul(x, delta)
	delta0 := suite.Point().Mul(x0, nil)
	delta0b, _ := delta0.MarshalBinary()
	delta0Bar, err := paillier.Encrypt(publicKey, delta0b)
	if err != nil {
		fmt.Println(err)
	}

	signSuite := edwards25519.NewBlakeSHA256Ed25519()
	theta, _ := schnorr.Sign(signSuite, x, delta0b)
	thetaBar, err := paillier.Encrypt(publicKey, theta)

	ORandGen := func() ([]byte, *ProofSignature) {
		k := suite.Scalar().Pick(suite.XOF([]byte("k")))
		h := hash1(suite, m)
		gamma := suite.Point().Mul(x0, h)
		g2 := suite.Point().Base()
		g2k := suite.Point().Mul(k, g2)
		hk := suite.Point().Mul(k, h)
		c := hash3(suite, g2, h, v, gamma, g2k, hk)
		y := hash2(suite, gamma)
		s := suite.Scalar().Add(suite.Scalar().Mul(c, x0), k)
		sb, _ := s.MarshalBinary()
		sBar, _ := paillier.Encrypt(publicKey, sb)

		return y, &ProofSignature{
			Gamma: gamma,
			C:     c,
			S:     sBar,
			Delta: delta0Bar,
			Theta: thetaBar,
		}
	}

	return ORandGen()
}
