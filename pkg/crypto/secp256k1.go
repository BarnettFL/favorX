package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

// Secp256k1PrivateKey is a Secp256k1 private key
type Secp256k1PrivateKey btcec.PrivateKey

// Secp256k1PublicKey is a Secp256k1 public key
type Secp256k1PublicKey btcec.PublicKey

func GenerateSecp256k1Key() (*Secp256k1PrivateKey, error) {
	key, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	k := (*Secp256k1PrivateKey)(key)
	return k, nil
}

// DecodeSecp256k1PrivateKey decodes raw ECDSA private key.
func DecodeSecp256k1PrivateKey(data []byte) (k *Secp256k1PrivateKey, err error) {
	if len(data) != btcec.PrivKeyBytesLen {
		return nil, fmt.Errorf("expected secp256k1 data size to be %d", btcec.PrivKeyBytesLen)
	}
	pk := Secp256k1PrivateKeyFromBytes(data)
	return pk, nil
}

// Secp256k1PrivateKeyFromBytes returns an ECDSA private key based on
// the byte slice.
func Secp256k1PrivateKeyFromBytes(data []byte) *Secp256k1PrivateKey {
	privk, _ := btcec.PrivKeyFromBytes(btcec.S256(), data)
	return (*Secp256k1PrivateKey)(privk)
}

func (k *Secp256k1PrivateKey) Equals(o Key) bool {
	sk, ok := o.(*Secp256k1PrivateKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.GetPublic().Equals(sk.GetPublic())
}

func (k *Secp256k1PrivateKey) Raw() ([]byte, error) {
	return (*btcec.PrivateKey)(k).Serialize(), nil
}

func (k *Secp256k1PrivateKey) Type() KeyType {
	return KeyType_Secp256k1
}

func (k *Secp256k1PrivateKey) Generic() PrivateKey {
	return k
}

func (k *Secp256k1PrivateKey) GetPublic() PublicKey {
	return (*Secp256k1PublicKey)((*btcec.PrivateKey)(k).PubKey())
}

func (k *Secp256k1PrivateKey) IntoKey() interface{} {
	return (*ecdsa.PrivateKey)(k)
}

func (k *Secp256k1PublicKey) GetHash() ([]byte, error) {
	if k.X == nil || k.Y == nil {
		return nil, errors.New("invalid public key")
	}
	pubBytes := elliptic.Marshal(btcec.S256(), k.X, k.Y)
	pubHash, err := LegacyKeccak256(pubBytes[1:])
	if err != nil {
		return nil, err
	}
	return pubHash, nil
}

func (k *Secp256k1PublicKey) Equals(o Key) bool {
	sk, ok := o.(*Secp256k1PublicKey)
	if !ok {
		return basicEquals(k, o)
	}

	return (*btcec.PublicKey)(k).IsEqual((*btcec.PublicKey)(sk))
}

func (k *Secp256k1PublicKey) Raw() ([]byte, error) {
	return (*btcec.PublicKey)(k).SerializeCompressed(), nil
}

func (k *Secp256k1PublicKey) Type() KeyType {
	return KeyType_Secp256k1
}

func (k *Secp256k1PublicKey) Generic() PublicKey {
	return k
}

func (k *Secp256k1PublicKey) IntoKey() interface{} {
	return (*ecdsa.PublicKey)(k)
}
