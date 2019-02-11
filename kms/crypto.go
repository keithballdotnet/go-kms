package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	mathrand "math/rand"

	"golang.org/x/crypto/pbkdf2"
)

// AesGCMEncrypt Encrypt data using AES with the GCM cipher mode (Gives Confidentiality and Authenticity)
func AesGCMEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return append(nonce, ciphertext...), nil
}

// AesGCMDecrypt Decrypt data using AES with the GCM cipher mode (Gives Confidentiality and Authenticity)
func AesGCMDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("Data to decrypt is too small")
	}

	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// GetHmac256 will generate a HMAC hash encoded to base64
func GetHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// DeriveKey will generate a AES key from a passphrase
func DeriveAESKey(passphrase string, salt []byte) []byte {
	// Create key
	return pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha1.New)
}

// Get a random number
func GetRandomInt(min, max int) int {

	// Generate a Crypto random seed from the OS
	// We should not use the time as the seed as this will lead to predicatable PINs
	var n int64
	binary.Read(rand.Reader, binary.LittleEndian, &n)
	mathrand.Seed(n)

	// Now get a number from the range desired
	return mathrand.Intn(max-min) + min
}

// Generate a Random secret encoded as a b32 string
// If the length is <= 0, a default length of 10 bytes will
// be used, which will generate a secret of length 16.
func RandomSecret(length int) string {
	if length <= 0 {
		length = 10
	}

	// Get a random based on a random int.  Based off OS not based on Time.
	rnd := mathrand.New(mathrand.NewSource(int64(GetRandomInt(100000, 999999))))

	secret := make([]byte, length)
	for i, _ := range secret {
		secret[i] = byte(rnd.Int31() % 256)
	}
	return base32.StdEncoding.EncodeToString(secret)
}
