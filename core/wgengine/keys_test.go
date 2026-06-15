package wgengine

import "testing"

func TestKeyGenerateAndDerive(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	if priv == (Key{}) {
		t.Fatal("private key is all-zero")
	}
	pub := priv.PublicKey()
	if pub == (Key{}) {
		t.Fatal("public key is all-zero")
	}
	if pub == priv {
		t.Fatal("public key equals private key")
	}
	// Derivation is deterministic.
	if priv.PublicKey() != pub {
		t.Fatal("PublicKey is not deterministic")
	}
}

func TestKeyHex(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	if len(priv.Hex()) != 64 {
		t.Fatalf("Hex len = %d, want 64", len(priv.Hex()))
	}
}

func TestDistinctKeys(t *testing.T) {
	a, _ := GeneratePrivateKey()
	b, _ := GeneratePrivateKey()
	if a == b {
		t.Fatal("two generated keys are identical")
	}
}
