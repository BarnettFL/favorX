package address_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/FavorLabs/favorX/pkg/address"
	"github.com/FavorLabs/favorX/pkg/crypto"
	ma "github.com/multiformats/go-multiaddr"
)

func TestBzzAddress(t *testing.T) {
	node1ma, err := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1634/p2p/16Uiu2HAkx8ULY8cTXhdVAcMmLcH9AsTKz6uBQ7DPLKRjMLgBVYkA")
	if err != nil {
		t.Fatal(err)
	}

	privateKey1, err := crypto.GenerateSecp256k1Key()
	if err != nil {
		t.Fatal(err)
	}

	overlay, err := crypto.NewOverlayAddress(crypto.FromPublicKey(privateKey1.GetPublic()), 3)
	if err != nil {
		t.Fatal(err)
	}
	signer1 := crypto.NewDefaultSigner(privateKey1.IntoKey().(*ecdsa.PrivateKey))

	bzzAddress, err := address.NewAddress(signer1, node1ma, overlay, 3)
	if err != nil {
		t.Fatal(err)
	}

	bzzAddress2, err := address.ParseAddress(node1ma.Bytes(), overlay.Bytes(), bzzAddress.Signature, 3)
	if err != nil {
		t.Fatal(err)
	}

	if !bzzAddress.Equal(bzzAddress2) {
		t.Fatalf("got %s expected %s", bzzAddress2, bzzAddress)
	}

	bytes, err := bzzAddress.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	var newbzz address.Address
	if err := newbzz.UnmarshalJSON(bytes); err != nil {
		t.Fatal(err)
	}

	if !newbzz.Equal(bzzAddress) {
		t.Fatalf("got %s expected %s", newbzz, bzzAddress)
	}
}
