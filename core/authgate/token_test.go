package authgate

import (
	"testing"
	"time"
)

func TestTokenRoundTripAndVerify(t *testing.T) {
	psk := []byte("super-secret-psk")
	dev := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	now := time.Unix(1_700_000_000, 0)

	raw, err := MakeToken(psk, dev, now)
	if err != nil {
		t.Fatalf("MakeToken: %v", err)
	}
	if len(raw) != TokenSize {
		t.Fatalf("token size = %d, want %d", len(raw), TokenSize)
	}
	tok, err := ParseToken(raw)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if tok.DeviceID != dev {
		t.Fatalf("DeviceID = %x, want %x", tok.DeviceID, dev)
	}
	if err := tok.Verify(psk, now, 30*time.Second); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTokenWrongPSK(t *testing.T) {
	dev := [16]byte{1}
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken([]byte("psk-a"), dev, now)
	tok, _ := ParseToken(raw)
	if err := tok.Verify([]byte("psk-b"), now, 30*time.Second); err == nil {
		t.Fatal("Verify with wrong PSK: want error, got nil")
	}
}

func TestTokenTamperedMAC(t *testing.T) {
	psk := []byte("psk")
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, now)
	raw[TokenSize-1] ^= 0xFF // flip a MAC bit
	tok, _ := ParseToken(raw)
	if err := tok.Verify(psk, now, 30*time.Second); err == nil {
		t.Fatal("Verify with tampered MAC: want error, got nil")
	}
}

func TestTokenStaleTimestamp(t *testing.T) {
	psk := []byte("psk")
	issued := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, issued)
	tok, _ := ParseToken(raw)
	later := issued.Add(5 * time.Minute)
	if err := tok.Verify(psk, later, 30*time.Second); err == nil {
		t.Fatal("Verify with stale timestamp: want error, got nil")
	}
}

func TestParseTokenWrongSize(t *testing.T) {
	if _, err := ParseToken(make([]byte, TokenSize-1)); err == nil {
		t.Fatal("ParseToken(short): want error, got nil")
	}
}

func TestEnrollTokenRoundTrip(t *testing.T) {
	psk := []byte("enroll-psk")
	uid := [16]byte{9, 9, 9}
	now := time.Unix(1_700_000_000, 0)
	raw, err := MakeEnrollToken(psk, uid, now)
	if err != nil {
		t.Fatalf("MakeEnrollToken: %v", err)
	}
	if len(raw) != TokenSize {
		t.Fatalf("token size = %d, want %d", len(raw), TokenSize)
	}
	tok, err := ParseToken(raw)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if tok.Kind != KindEnroll {
		t.Fatalf("Kind = %d, want KindEnroll", tok.Kind)
	}
	if tok.DeviceID != uid {
		t.Fatalf("id = %x, want %x", tok.DeviceID, uid)
	}
	if err := tok.Verify(psk, now, 30*time.Second); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestMakeTokenIsDeviceKind(t *testing.T) {
	raw, _ := MakeToken([]byte("psk"), [16]byte{1}, time.Unix(1_700_000_000, 0))
	tok, _ := ParseToken(raw)
	if tok.Kind != KindDevice {
		t.Fatalf("MakeToken kind = %d, want KindDevice", tok.Kind)
	}
}

func TestTokenKindIsBoundByMAC(t *testing.T) {
	// Flipping the kind byte of a device token must invalidate the MAC.
	psk := []byte("psk")
	now := time.Unix(1_700_000_000, 0)
	raw, _ := MakeToken(psk, [16]byte{1}, now)
	raw[1] = KindEnroll // tamper the kind byte
	tok, _ := ParseToken(raw)
	if err := tok.Verify(psk, now, 30*time.Second); err == nil {
		t.Fatal("kind tamper accepted; MAC must bind kind")
	}
}
