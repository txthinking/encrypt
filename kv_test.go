package encrypt

import "testing"

func TestKV(t *testing.T) {
	kv := &KV{
		AESKey: []byte("qwertyuiopasdfghjklzqwertyuiopqw"),
	}

	c, err := kv.Encrypt("hello", "world")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c)
	v1, err := kv.Decrypt(c, "hello", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(v1)

	type hi struct {
		A string
		B int
	}
	a := &hi{
		A: "hello",
		B: 1,
	}
	c, err = kv.EncryptStruct("hello", a)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(c)
	a1 := &hi{}
	err = kv.DecryptStruct(c, a1, "hello", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(a1)
}
