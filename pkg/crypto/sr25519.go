package crypto

import (
	"crypto/rand"

	"github.com/oasisprotocol/curve25519-voi/primitives/sr25519"
)

// Sr25519PrivateKey is a sr25519 private key.
type Sr25519PrivateKey struct {
	k *sr25519.MiniSecretKey
}

// Sr25519PublicKey is a sr25519 public key.
type Sr25519PublicKey struct {
	k *sr25519.PublicKey
}

func GenerateSr25519Key() (*Sr25519PrivateKey, error) {
	pk, err := sr25519.GenerateMiniSecretKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Sr25519PrivateKey{
		k: pk,
	}, nil
}

// DecodeSr25519PrivateKey decodes raw Sr25519 private key.
func DecodeSr25519PrivateKey(data []byte) (k *Sr25519PrivateKey, err error) {
	var pk sr25519.MiniSecretKey

	err = pk.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}

	return &Sr25519PrivateKey{
		k: &pk,
	}, nil
}

func (k *Sr25519PrivateKey) Equals(o Key) bool {
	edk, ok := o.(*Sr25519PrivateKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

func (k *Sr25519PrivateKey) Raw() ([]byte, error) {
	return k.k.MarshalBinary()
}

func (k *Sr25519PrivateKey) Type() KeyType {
	return KeyType_Sr25519
}

func (k *Sr25519PrivateKey) Generic() PrivateKey {
	return k
}

func (k *Sr25519PrivateKey) IntoKey() interface{} {
	return k.k
}

func (k *Sr25519PrivateKey) GetPublic() PublicKey {
	expandKey := k.k.ExpandUniform()

	return &Sr25519PublicKey{k: expandKey.PublicKey()}
}

func (k *Sr25519PublicKey) GetHash() ([]byte, error) {
	data, err := k.Raw()
	if err != nil {
		return nil, err
	}
	pubHash, err := LegacyKeccak256(data)
	if err != nil {
		return nil, err
	}
	return pubHash, nil
}

func (k *Sr25519PublicKey) Equals(o Key) bool {
	edk, ok := o.(*Sr25519PublicKey)
	if !ok {
		return basicEquals(k, o)
	}

	return k.k.Equal(edk.k)
}

func (k *Sr25519PublicKey) Raw() ([]byte, error) {
	return k.k.MarshalBinary()
}

func (k *Sr25519PublicKey) Type() KeyType {
	return KeyType_Sr25519
}

func (k *Sr25519PublicKey) Generic() PublicKey {
	return k
}

func (k *Sr25519PublicKey) IntoKey() interface{} {
	return k.k
}
