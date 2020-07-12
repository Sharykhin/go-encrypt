package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func createHash(key string) string  {
	hasher := md5.New()
	hasher.Write([]byte(key))

	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)
	cipherText := gcm.Seal(nonce, nonce, data, nil)

	return cipherText
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open(nil, nonce, cipherText, nil)

	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	_, _ = f.Write(encrypt(data, passphrase))

}

func decryptFile(filename, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)

	return decrypt(data, passphrase)
}

func main() {
	cipherText := encrypt([]byte("Hello world"), "password")
	fmt.Println(cipherText, string(cipherText))

	plainText := decrypt(cipherText, "password")
	fmt.Println(string(plainText))

	encryptFile("example.log", []byte("Hello filename"), "password")
	data := decryptFile("example.log", "password")
	fmt.Println(string(data))
}
