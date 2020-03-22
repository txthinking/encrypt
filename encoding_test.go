package encrypt

import (
	"testing"
)

func TestUTF8GBK(t *testing.T) {
	g, err := UTF82GBK([]byte("梦一场"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(g)

	u, err := GBK2UTF8(g)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(u)
}
