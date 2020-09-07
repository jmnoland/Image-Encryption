package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"encoding/json"
	"os"
)

type Settings struct {
	BasePath string `json:"BasePath"`
	OutputPath string `json:"OutputPath"`
	Password string `json:"Password"`
	Encrypt bool `json:"Encrypt"`
}

type FileDetails struct {
	Name string
	IsDir bool
}

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

func getSettings() Settings {
	jsonFile, err := os.Open("settings.json")
	checkErr(err)
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var settings Settings
	json.Unmarshal(byteValue, &settings)

	defer jsonFile.Close()
	return settings
}

func IOReadDir(root string) ([]FileDetails, error) {
    var files []FileDetails
    fileInfo, err := ioutil.ReadDir(root)
    if err != nil {
        return files, err
    }

    for _, file := range fileInfo {
		details := FileDetails { IsDir: file.IsDir(), Name: file.Name() }
        files = append(files, details)
    }
    return files, nil
}

func ReadImage(key *[32]byte, path string, fileName string, outputPath string) {
	file, err := os.Open(path + fileName)
	checkErr(err)
	fstats, err := file.Stat()
	checkErr(err)
	data := make([]byte, fstats.Size())
	checkErr(err)
	en, err := Encrypt(data, key)
	checkErr(err)
	SaveFile(outputPath + fileName, en)
}

func main() {
	settings := getSettings()

	key := NewEncryptionKey()

	files, err := IOReadDir(settings.BasePath)
	checkErr(err)

	for _, file := range files {
		if !file.IsDir {
			ReadImage(key, settings.BasePath, file.Name, settings.OutputPath)
		}
	}

}
