package encrypt

import (
	"encoding/hex"
	"testing"
)

func TestHkdfSha256(t *testing.T) {
	info := []byte{0x62, 0x72, 0x6f, 0x6f, 0x6b}
	r, _, err := HkdfSha256RandomSalt([]byte("hello"), info, 12)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(r), len(r))
}
