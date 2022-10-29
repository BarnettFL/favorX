package crypto

import (
	"crypto/ecdsa"

	"github.com/FavorLabs/favorX/pkg/boson"
	"golang.org/x/crypto/sha3"
)

// RecoverFunc is a function to recover the public key from a signature
type RecoverFunc func(signature, data []byte) (*ecdsa.PublicKey, error)

const (
	AddressSize = 20
)

// NewOverlayAddress constructs a Address from ECDSA public key.
func NewOverlayAddress(p PublicKey, networkID uint64) (boson.Address, error) {
	pubHash, err := p.GetHash()
	if err != nil {
		return boson.ZeroAddress, err
	}
	overlay := sha3.Sum256(pubHash)
	return boson.NewAddress(overlay[:]), nil
}

// NewEthereumAddress returns a binary representation of ethereum blockchain address.
// This function is based on github.com/ethereum/go-ethereum/crypto.PubkeyToAddress.
func NewEthereumAddress(p PublicKey) ([]byte, error) {
	pubHash, err := p.GetHash()
	if err != nil {
		return nil, err
	}
	return pubHash[12:], err
}

func LegacyKeccak256(data []byte) ([]byte, error) {
	var err error
	hasher := sha3.NewLegacyKeccak256()
	_, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), err
}
