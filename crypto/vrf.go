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
	paillier "github.com/ColdFaceMagicMan/go-go-gadget-paillier"
	"go.dedis.ch/kyber/v3"
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

// VrfKeyGen generates a public key, private key, public key point, and cryptographic suite.
func vrfKeyGenFromSeed(seed [32]byte) (*paillier.PrivateKey, kyber.Point, kyber.Scalar) {
	privKey, err := paillier.GenerateKey(rand.Reader, 1024)
	if err != nil {

	}
	suite := GetPP()
	x := suite.Scalar().Pick(suite.XOF([]byte("x")))

	v := suite.Point().Mul(x, nil)

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

	pubBytes, _ := pubKeys.MarshalBinary()
	prvBytes, _ := privKeys.MarshalBinary()
	return pubBytes, prvBytes
}

// VrfKeygen generates a random VRF keypair.
func VrfKeygen() (pub VrfPubkey, priv VrfPrivkey) {
	strs := make([]byte, 32)
	rand.Read(strs)
	seed := [32]byte{}
	copy(seed[:], strs)

	return VrfKeygenFromSeed(seed)
}

// Pubkey returns the public key that corresponds to the given private key.
func (sk VrfPrivkey) Pubkey() (pk VrfPubkey) {
	x := sk
	prvKey := PrivKeys{}
	prvKey.UnmarshalBinary(x)
	pks := PubKeys{
		ProofEncKey: &prvKey.ProofDecKey.PublicKey,
		VrfKey:      GetPP().Point().Mul(prvKey.VrfKey, nil),
	}
	pkBytes, _ := pks.MarshalBinary()
	return pkBytes
}

func (sk VrfPrivkey) proveBytes(msg []byte) (proof VrfProof, ok bool) {
	pkBytes := sk.Pubkey()
	pk := PubKeys{}
	pk.UnmarshalBinary(pkBytes)
	//_, sig := RandGen(GetPP(), msg, sk, pk.VrfKey, pk.ProofEncKey)

	prvKey := PrivKeys{}
	prvKey.UnmarshalBinary(sk)

	_, sig := Obf(GetPP(), msg, prvKey.VrfKey, pk.VrfKey, pk.ProofEncKey)

	sig2 := ProofDec(sig, prvKey.ProofDecKey)
	proof, _ = sig2.MarshalJSON()
	sig3 := ProofSignature{}
	sig3.UnmarshalJSON(proof)

	return proof, true
}

// Prove constructs a VRF Proof for a given Hashable.
// ok will be false if the private key is malformed.
func (sk VrfPrivkey) Prove(message Hashable) (proof VrfProof, ok bool) {
	return sk.proveBytes(HashRep(message))
}

// Hash converts a VRF proof to a VRF output without verifying the proof.
// TODO: Consider removing so that we don't accidentally hash an unverified proof
func (proof VrfProof) Hash() (hash VrfOutput, ok bool) {
	sig := ProofSignature{}
	sig.UnmarshalJSON(proof)

	tmp := hash2(GetPP(), sig.Gamma)
	copy(hash[:], tmp)

	return hash, true
}

func (pk VrfPubkey) verifyBytes(proof VrfProof, msg []byte) (bool, VrfOutput) {
	sig := ProofSignature{}
	sig.UnmarshalJSON(proof)

	p := PubKeys{}
	p.UnmarshalBinary(pk)
	return Verify(GetPP(), p.VrfKey, msg, &sig)
}

// Verify checks a VRF proof of a given Hashable. If the proof is valid the pseudorandom VrfOutput will be returned.
// For a given public key and message, there are potentially multiple valid proofs.
// However, given a public key and message, all valid proofs will yield the same output.
// Moreover, the output is indistinguishable from random to anyone without the proof or the secret key.
func (pk VrfPubkey) Verify(p VrfProof, message Hashable) (bool, VrfOutput) {
	return pk.verifyBytes(p, HashRep(message))
}
