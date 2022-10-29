package crypto

import (
	"crypto/subtle"
)

type KeyType int32

const (
	KeyType_Secp256k1 KeyType = 0
	KeyType_Sr25519   KeyType = 1
)

type Key interface {
	Equals(Key) bool
	Raw() ([]byte, error)
	Type() KeyType
}

type PrivateKey interface {
	Key
	IntoKey() interface{}
	Generic() PrivateKey
	GetPublic() PublicKey
}

type PublicKey interface {
	Key
	IntoKey() interface{}
	Generic() PublicKey
	GetHash() ([]byte, error)
}

func basicEquals(k1, k2 Key) bool {
	if k1.Type() != k2.Type() {
		return false
	}

	a, err := k1.Raw()
	if err != nil {
		return false
	}
	b, err := k2.Raw()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func FromPrivateKey(k interface{}) PrivateKey {
	switch i := k.(type) {
	case *Secp256k1PrivateKey:
		return i
	case *Sr25519PrivateKey:
		return i
	default:
		panic("unsupported private key type")
	}
}

func FromPublicKey(k interface{}) PublicKey {
	switch i := k.(type) {
	case *Secp256k1PublicKey:
		return i
	case *Sr25519PublicKey:
		return i
	default:
		panic("unsupported private key type")
	}
}
