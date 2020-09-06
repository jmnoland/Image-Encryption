package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
)


func NewEncryptionKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func SaveFile(fileName string, content []byte) {
	err := ioutil.WriteFile(fileName, content, 0644)
	checkErr(err)
}

func main() {
	file, err := os.Open("test.jpg")
	checkErr(err)
	fstats, err := file.Stat()
	checkErr(err)
	data := make([]byte, fstats.Size())
	checkErr(err)

	key := NewEncryptionKey()

	en, err := Encrypt(data, key)
	checkErr(err)
	SaveFile("encrypted.jpg", en)

	pl, err := Decrypt(en, key)
	SaveFile("decrypted.jpg", pl)
	checkErr(err)

}
