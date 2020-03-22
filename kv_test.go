package encrypt

import "testing"

func TestKV(t *testing.T) {
	kv := &KV{
		AESKey: []byte("qwertyuiopasdfghjklzqwertyuiopqw"),
	}
	k := "t"

	v := "hello"
	c, err := kv.Encrypt(k, v)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c)
	v1, err := kv.Decrypt(c, k, 60)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(v1)
}
