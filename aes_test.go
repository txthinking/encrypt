package encrypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESMake256Key(t *testing.T) {
	KEY := []byte("12345678901234567890123456789012")
	k := AESMake256Key(KEY)
	if len(k) != 32 {
		t.Fatal("Not 32 length")
	}
}

func TestAESCFB(t *testing.T) {
	KEY := []byte("12345678901234567890123456789012")
	s := []byte("txthinking")
	t.Log("input:", hex.EncodeToString(s), len(s))

	r, err := AESCFBEncrypt(s, KEY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypt:", hex.EncodeToString(r), len(r))

	r, err = AESCFBDecrypt(r, KEY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", hex.EncodeToString(r), len(r))
	if string(s) != string(r) {
		t.Fatal("AES CFB Error")
	}
}

func TestAESCBC(t *testing.T) {
	KEY := []byte("12345678901234567890123456789012")
	s := []byte("txthinking")
	t.Log("input:", hex.EncodeToString(s), len(s))

	sp := PKCS5Padding(s, 16)
	r, err := AESCBCEncrypt(sp, KEY)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypt:", hex.EncodeToString(r), len(r))

	r, err = AESCBCDecrypt(r, KEY)
	if err != nil {
		t.Fatal(err)
	}
	r, err = PKCS5UnPadding(r)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", hex.EncodeToString(r), len(r))

	if string(s) != string(r) {
		t.Fatal("AES CBC Error")
	}
}

func TestAESGCM(t *testing.T) {
	k := []byte("12345678901234567890123456789012")
	n := []byte("123456789012")

	s := []byte("12345678901234567890")
	t.Log("input:", hex.EncodeToString(s), len(s))

	c, err := AESGCMEncrypt(s, k, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypt:", hex.EncodeToString(c), len(c))

	s1, err := AESGCMDecrypt(c, k, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", hex.EncodeToString(s1), len(s1))
	if !bytes.Equal(s, s1) {
		t.Fatal("aes gcm error")
	}

	s = []byte("12")
	t.Log("input:", hex.EncodeToString(s), len(s))

	c, err = AESGCMEncrypt(s, k, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("encrypt:", hex.EncodeToString(c), len(c))

	s1, err = AESGCMDecrypt(c, k, n)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("output:", hex.EncodeToString(s1), len(s1))
	if !bytes.Equal(s, s1) {
		t.Fatal("aes gcm error")
	}
}
