package testpackage

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func BenchmarkEncryptOAEP(b *testing.B) {
	// Generate an RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal("Error generating RSA key:", err)
	}

	for n := 0; n < b.N; n++ {

		nonceSize := 32

		// Generate a random nonce
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			b.Fatal("Error generating nonce:", err)
		}

		// Encrypt the nonce
		_, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &privateKey.PublicKey, nonce, nil)
		if err != nil {
			b.Fatal("Error encrypting nonce:", err)
		}
	}
}

func BenchmarkSignPSS(b *testing.B) {
	var err error
	var hash [32]byte

	jsonStr := `{"PubKey": "encryptedPub", "Share": "encryptedShare", "OtherData": "dummyData"}`
	jsonBytes := []byte(jsonStr)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal("Error generating RSA key:", err)
	}

	for n := 0; n < b.N; n++ {
		jsonBytesCopy := make([]byte, len(jsonBytes))
		copy(jsonBytesCopy, jsonBytes)

		hash = sha256.Sum256(jsonBytesCopy)
		_, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
