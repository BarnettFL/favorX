package addressbook_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/FavorLabs/favorX/pkg/address"
	"github.com/FavorLabs/favorX/pkg/addressbook"
	"github.com/FavorLabs/favorX/pkg/boson"
	"github.com/FavorLabs/favorX/pkg/crypto"
	"github.com/FavorLabs/favorX/pkg/statestore/mock"
	ma "github.com/multiformats/go-multiaddr"
)

type bookFunc func(t *testing.T) (book addressbook.Interface)

func TestInMem(t *testing.T) {
	run(t, func(t *testing.T) addressbook.Interface {
		store := mock.NewStateStore()
		book := addressbook.New(store)
		return book
	})
}

func run(t *testing.T, f bookFunc) {
	store := f(t)
	addr1 := boson.NewAddress([]byte{0, 1, 2, 3})
	addr2 := boson.NewAddress([]byte{0, 1, 2, 4})
	multiaddr, err := ma.NewMultiaddr("/ip4/1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	pk, err := crypto.GenerateSecp256k1Key()
	if err != nil {
		t.Fatal(err)
	}

	bzzAddr, err := address.NewAddress(crypto.NewDefaultSigner(pk.IntoKey().(*ecdsa.PrivateKey)), multiaddr, addr1, 1)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Put(addr1, *bzzAddr)
	if err != nil {
		t.Fatal(err)
	}

	v, err := store.Get(addr1)
	if err != nil {
		t.Fatal(err)
	}

	if !bzzAddr.Equal(v) {
		t.Fatalf("expectted: %s, want %s", v, multiaddr)
	}

	notFound, err := store.Get(addr2)
	if err != addressbook.ErrNotFound {
		t.Fatal(err)
	}

	if notFound != nil {
		t.Fatalf("expected nil got %s", v)
	}

	overlays, err := store.Overlays()
	if err != nil {
		t.Fatal(err)
	}

	if len(overlays) != 1 {
		t.Fatalf("expected overlay len %v, got %v", 1, len(overlays))
	}

	addresses, err := store.Addresses()
	if err != nil {
		t.Fatal(err)
	}

	if len(addresses) != 1 {
		t.Fatalf("expected addresses len %v, got %v", 1, len(addresses))
	}
}
