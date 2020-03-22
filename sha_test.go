package encrypt

import (
	"testing"
)

func TestSHA1(t *testing.T) {
	s := "tx"
	s = SHA1(s)
	t.Log(s)
}
