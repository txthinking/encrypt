package encrypt

import (
	"testing"
)

func TestMD5(t *testing.T) {
	s := "tx"
	s = MD5(s)
	t.Log(s)
}
