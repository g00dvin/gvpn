package session

import "testing"

func TestBindRoundTrip(t *testing.T) {
	var sid [sessionIDSize]byte
	var tok [resumeTokenSize]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	for i := range tok {
		tok[i] = byte(0xA0 + i)
	}

	b := marshalBind(sid, tok)
	if len(b) != bindPayloadSize {
		t.Fatalf("marshalBind len = %d, want %d", len(b), bindPayloadSize)
	}
	gotSID, gotTok, err := parseBind(b)
	if err != nil {
		t.Fatalf("parseBind: %v", err)
	}
	if gotSID != sid {
		t.Fatalf("sid = %x, want %x", gotSID, sid)
	}
	if gotTok != tok {
		t.Fatalf("token = %x, want %x", gotTok, tok)
	}
}

func TestParseBindWrongSize(t *testing.T) {
	if _, _, err := parseBind(make([]byte, bindPayloadSize-1)); err == nil {
		t.Fatal("parseBind(short): want error, got nil")
	}
}

func TestZeroSessionIDSentinel(t *testing.T) {
	var z [sessionIDSize]byte
	if zeroSessionID != z {
		t.Fatal("zeroSessionID is not all-zero")
	}
}
