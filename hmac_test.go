package encrypt

import (
	"encoding/hex"
	"testing"
)

func TestHmacSha256(t *testing.T) {
	KEY := []byte("12345678901234567890123456789012")
	s := []byte("txthinking")
	r, err := HmacSha256(s, KEY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(r), len(r))

	ok, err := CheckHmacSha256(s, r, KEY)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("HmacSha256 Error")
	}

	r, err = HmacSha1(s, KEY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(r), len(r))

	ok, err = CheckHmacSha1(s, r, KEY)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("HmacSha1 Error")
	}
}
