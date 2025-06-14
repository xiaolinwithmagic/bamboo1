package crypto

import (
	"errors"
	"sync"
	"github.com/kilic/bls12-381"
)

type PublicKey *bls12381.PointG1
type PrivateKey *bls12381.Scalar
type Signature *bls12381.PointG2

var (
	keyStore = make(map[string]PublicKey)
	storeLock sync.RWMutex
)

// GenerateKeyPair generates a new BLS private and public key pair.
func GenerateKeyPair() (PrivateKey, PublicKey) {
	sk := bls12381.NewKeyGenerate()
	pk := bls12381.NewG1().MulScalar(bls12381.NewG1().One(), sk)
	return sk, pk
}

// Sign signs the message with the given private key.
func Sign(sk PrivateKey, msg []byte) Signature {
	hash := bls12381.NewG2().HashToCurve(msg, []byte("domain"))
	sig := bls12381.NewG2().MulScalar(hash, sk)
	return sig
}

// Verify verifies the signature with the given public key and message.
func Verify(sig Signature, pk PublicKey, msg []byte) bool {
	hash := bls12381.NewG2().HashToCurve(msg, []byte("domain"))
	pairing1, _ := bls12381.NewEngine().AddPair(pk, hash)
	pairing2, _ := bls12381.NewEngine().AddPair(bls12381.NewG1().One(), sig)
	return pairing1.IsEqual(pairing2)
}

// AggregatePublicKeys aggregates the public keys of given node IDs.
func AggregatePublicKeys(signers []string) PublicKey {
	agg := bls12381.NewG1().Zero()
	for _, id := range signers {
		pk := GetPublicKey(id)
		agg = bls12381.NewG1().Add(agg, pk)
	}
	return agg
}

// RemovePubKeyFromAgg subtracts a public key from an aggregated public key.
func RemovePubKeyFromAgg(agg, pk PublicKey) PublicKey {
	neg := bls12381.NewG1().Neg(pk)
	return bls12381.NewG1().Add(agg, neg)
}

// VerifyAggSig verifies the aggregated signature against the given aggregated public key and message.
func VerifyAggSig(sig Signature, aggPK PublicKey, msg []byte) bool {
	hash := bls12381.NewG2().HashToCurve(msg, []byte("domain"))
	pairing1, _ := bls12381.NewEngine().AddPair(aggPK, hash)
	pairing2, _ := bls12381.NewEngine().AddPair(bls12381.NewG1().One(), sig)
	return pairing1.IsEqual(pairing2)
}

// Key management
func StorePublicKey(id string, pk PublicKey) {
	storeLock.Lock()
	defer storeLock.Unlock()
	keyStore[id] = pk
}

func GetPublicKey(id string) PublicKey {
	storeLock.RLock()
	defer storeLock.RUnlock()
	return keyStore[id]
}

// Converts an ID (e.g., block or node ID) to byte slice.
func IDToByte(id interface{}) []byte {
	// Simplified: implement actual conversion
	return []byte{} // stub
}

// PubVerify checks a signature with the given public key and message.
func PubVerify(sig Signature, msg []byte, id string) (bool, error) {
	pk := GetPublicKey(id)
	if pk == nil {
		return false, errors.New("public key not found")
	}
	return Verify(sig, pk, msg), nil
}
