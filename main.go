package main

import (
    "crypto/aes"
    "crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/argon2"
	"errors"
	"strings"
	"io"
	"io/ioutil"
	"encoding/json"
	"os"
)

type Settings struct {
	BasePath string `json:"BasePath"`
	OutputPath string `json:"OutputPath"`
	Password string `json:"Password"`
	Salt string `json:"Salt"`
	Encrypt bool `json:"Encrypt"`
}

type FileDetails struct {
	Name string
	IsDir bool
}

var settings Settings

func NewEncryptionKey(password string, salt string) []byte {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	return key
}

func Encrypt(plaintext []byte, key []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
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

func Decrypt(ciphertext []byte, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := gcm.NonceSize()
	if len(ciphertext) < nonce {
		return nil, errors.New("malformed ciphertext")
	}
	return gcm.Open(nil,
		ciphertext[:nonce],
		ciphertext[nonce:],
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

func ProcessFile(key []byte, path string, fileName string, outputPath string) {
	data, err := ioutil.ReadFile(path + fileName)
	checkErr(err)
	var outputData []byte
	if settings.Encrypt {
		outputData, err = Encrypt(data, key)
		checkErr(err)
	} else {
		outputData, err = Decrypt(data, key)
		checkErr(err)
	}
	SaveFile(outputPath + fileName, outputData)
}

func Explorer(key []byte, currentPath string, outputPath string) {
	files, err := IOReadDir(currentPath)
	checkErr(err)

	for _, file := range files {
		if !file.IsDir {
			ProcessFile(key, currentPath, file.Name, outputPath + currentPath)
		} else {
			var path strings.Builder
			path.WriteString(currentPath)
			path.WriteString(file.Name)
			path.WriteString("/")
			os.MkdirAll(outputPath + path.String(), os.ModePerm)
			Explorer(key, path.String(), outputPath)
		}
	}
}

func main() {
	settings = getSettings()

	key := NewEncryptionKey(settings.Password, settings.Salt)
	Explorer(key, settings.BasePath, settings.OutputPath)
}
