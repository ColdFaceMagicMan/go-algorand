// Copyright (C) 2019-2024 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package crypto

// #cgo CFLAGS: -Wall -std=c99
// #cgo darwin,amd64 CFLAGS: -I${SRCDIR}/libs/darwin/amd64/include
// #cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libs/darwin/amd64/lib/libsodium.a
// #cgo linux,amd64 CFLAGS: -I${SRCDIR}/libs/linux/amd64/include
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/libs/linux/amd64/lib/libsodium.a
// #cgo linux,arm64 CFLAGS: -I${SRCDIR}/libs/linux/arm64/include
// #cgo linux,arm64 LDFLAGS: ${SRCDIR}/libs/linux/arm64/lib/libsodium.a
// #cgo linux,arm CFLAGS: -I${SRCDIR}/libs/linux/arm/include
// #cgo linux,arm LDFLAGS: ${SRCDIR}/libs/linux/arm/lib/libsodium.a
// #cgo windows,amd64 CFLAGS: -I${SRCDIR}/libs/windows/amd64/include
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/libs/windows/amd64/lib/libsodium.a
// #include <stdint.h>
// #include "sodium.h"
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func init() {
	if C.sodium_init() == -1 {
		panic("sodium_init() failed")
	}
}

// deprecated names + wrappers -- TODO remove

// VRFVerifier is a deprecated name for VrfPubkey
type VRFVerifier = VrfPubkey

// VRFVerifierMaxSize forwards to base implementation since it's expected by the msgp generated MaxSize functions
func VRFVerifierMaxSize() int {
	return VrfPubkeyMaxSize()
}

// VRFProof is a deprecated name for VrfProof
type VRFProof = VrfProof

// VRFSecrets is a wrapper for a VRF keypair. Use *VrfPrivkey instead
type VRFSecrets struct {
	_struct struct{} `codec:""`

	PK VrfPubkey
	SK VrfPrivkey
}

// GenerateVRFSecrets is deprecated, use VrfKeygen or VrfKeygenFromSeed instead
func GenerateVRFSecrets() *VRFSecrets {
	s := new(VRFSecrets)
	s.PK, s.SK = VrfKeygen()
	return s
}

// TODO: Go arrays are copied by value, so any call to e.g. VrfPrivkey.Prove() makes a copy of the secret key that lingers in memory.
// To avoid this, should we instead allocate memory for secret keys here (maybe even in the C heap) and pass around pointers?
// e.g., allocate a privkey with sodium_malloc and have VrfPrivkey be of type unsafe.Pointer?
type (
	// A VrfPrivkey is a private key used for producing VRF proofs.
	// Specifically, we use a 64-byte ed25519 private key (the latter 32-bytes are the precomputed public key)
	VrfPrivkey PrivKeys
	// A VrfPubkey is a public key that can be used to verify VRF proofs.
	VrfPubkey PubKeys
	// A VrfProof for a message can be generated with a secret key and verified against a public key, like a signature.
	// Proofs are malleable, however, for a given message and public key, the VRF output that can be computed from a proof is unique.
	VrfProof ProofSignature
	// VrfOutput is a 64-byte pseudorandom value that can be computed from a VrfProof.
	// The VRF scheme guarantees that such output will be unique
	VrfOutput []byte
)

type PrivKeys struct {
	ProofDecKey *paillier.PrivateKey
	VrfKey      kyber.Scalar
}

//func (k *PrivKeys) ToBytes() VrfPrivkey {
//	keyBytes, _ := json.Marshal(k)
//	fmt.Println(string(keyBytes))
//	return keyBytes
//}

type PubKeys struct {
	ProofEncKey *paillier.PublicKey
	VrfKey      kyber.Point
}

//
//func (k *PubKeys) ToBytes() VrfPubkey {
//	keyBytes, _ := json.Marshal(k)
//
//	buf := &bytes.Buffer{}
//	err := binary.Write(buf, binary.BigEndian, k)
//	if err != nil {
//	}
//
//	kk := &PubKeys{}
//	binary.Read(buf, binary.BigEndian, kk)
//
//	fmt.Println(string(keyBytes))
//	return keyBytes
//}

// VrfKeyGen generates a public key, private key, public key point, and cryptographic suite.
func vrfKeyGenFromSeed(seed [32]byte) (*paillier.PrivateKey, kyber.Point, kyber.Scalar) {
	bits := int(binary.BigEndian.Uint32(seed[:]))
	bits = 1234
	privKey, _ := paillier.GenerateKey(rand.Reader, bits)
	suite := GetPP()
	x := suite.Scalar().Pick(suite.XOF([]byte("x")))

	v := suite.Point().Mul(x, nil)
	//xBytes, _ := x.MarshalBinary()
	//vBytes, _ := v.MarshalBinary()

	//x2 := suite.Scalar()
	//x2.UnmarshalBinary(xBytes)
	//v = suite.Point()
	//v.UnmarshalBinary(vBytes)
	//fmt.Print(xBytes, vBytes)

	return privKey, v, x
}

// VrfKeygenFromSeed deterministically generates a VRF keypair from 32 bytes of (secret) entropy.
func VrfKeygenFromSeed(seed [32]byte) (pub VrfPubkey, priv VrfPrivkey) {
	pk, v, x := vrfKeyGenFromSeed(seed)

	pubKeys := PubKeys{
		ProofEncKey: &pk.PublicKey,
		VrfKey:      v,
	}

	privKeys := PrivKeys{
		ProofDecKey: pk,
		VrfKey:      x,
	}

	return VrfPubkey(pubKeys), VrfPrivkey(privKeys)
}

// VrfKeygen generates a random VRF keypair.
func VrfKeygen() (pub VrfPubkey, priv VrfPrivkey) {
	return VrfKeygenFromSeed([32]byte{})
}

func GetPP() Suite {
	if pp == nil {
		pp = edwards25519.NewBlakeSHA256Ed25519()
	}
	return pp
}

// Suite defines the cryptographic suite interface.
type Suite interface {
	kyber.Group
	kyber.Encoding
	kyber.XOFFactory
}

// Pubkey returns the public key that corresponds to the given private key.
func (sk VrfPrivkey) Pubkey() (pk VrfPubkey) {
	x := sk
	pks := PubKeys{
		ProofEncKey: &x.ProofDecKey.PublicKey,
		VrfKey:      GetPP().Point().Mul(sk.VrfKey, nil),
	}
	return VrfPubkey(pks)
}

func (sk VrfPrivkey) proveBytes(msg []byte) (proof VrfProof, ok bool) {
	pk := sk.Pubkey()
	_, sig := RandGen(GetPP(), msg, sk, pk.VrfKey, pk.ProofEncKey)

	sig2 := ProofDec(sig, sk.ProofDecKey)

	return VrfProof(*sig2), true
}

// Prove constructs a VRF Proof for a given Hashable.
// ok will be false if the private key is malformed.
func (sk VrfPrivkey) Prove(message Hashable) (proof VrfProof, ok bool) {
	return sk.proveBytes(HashRep(message))
}

// Hash converts a VRF proof to a VRF output without verifying the proof.
// TODO: Consider removing so that we don't accidentally hash an unverified proof
func (proof VrfProof) Hash() (hash VrfOutput, ok bool) {
	return hash2(GetPP(), proof.Gamma), true
}

func (pk VrfPubkey) verifyBytes(proof VrfProof, msg []byte) (bool, VrfOutput) {
	sig := ProofSignature(proof)

	return Verify(GetPP(), pk.VrfKey, msg, &sig)
}

// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
// For a given public key and message, there are potentially multiple valid proofs.
// However, given a public key and message, all valid proofs will yield the same output.
// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
func (pk VrfPubkey) Verify(p VrfProof, message Hashable) (bool, VrfOutput) {
	return pk.verifyBytes(p, HashRep(message))
}
