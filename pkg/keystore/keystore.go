package keystore

import (
	"errors"

	"github.com/FavorLabs/favorX/pkg/crypto"
)

// ErrInvalidPassword is returned when the password for decrypting content where
// private key is stored is not valid.
var ErrInvalidPassword = errors.New("invalid password")

// Service for managing keystore private keys.
type Service interface {
	// Key returns the private key for a specified name that was encrypted with
	// the provided password. If the private key does not exists it creates
	// a new one with a name and the password, and returns with created set
	// to true.
	Key(typ crypto.KeyType, name, password string) (k crypto.PrivateKey, created bool, err error)
	// Exists returns true if the key with specified name exists.
	Exists(name string) (bool, error)
	ExportKey(name, password string) ([]byte, error)
	ImportKey(name, password string, keyJson []byte) error
	ImportPrivateKey(name, password string, pk crypto.PrivateKey) (err error)
}
