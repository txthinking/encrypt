package encrypt

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// JSON Struct
func DecryptStructFrom(r io.Reader, v interface{}, k []byte) error {
	d, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	return DecryptStruct(d, v, k)
}

// JSON Struct
func DecryptStruct(d []byte, v interface{}, k []byte) error {
	d, err := AESCFBDecrypt(d, k)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(d, v); err != nil {
		return err
	}
	return nil
}

// JSON Struct
func EncryptStruct(v interface{}, k []byte) ([]byte, error) {
	d, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	d, err = AESCFBEncrypt(d, k)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func EncryptStructTo(w io.Writer, v interface{}, k []byte) error {
	d, err := EncryptStruct(v, k)
	if err != nil {
		return err
	}
	_, err = w.Write(d)
	if err != nil {
		return err
	}
	return nil
}
