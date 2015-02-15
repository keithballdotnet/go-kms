package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"time"
)

// Path to the certificate
var CertifcatePath = filepath.Join(os.TempDir(), "blocker", "cert.pem")

// Path to the private key
var KeyPath = filepath.Join(os.TempDir(), "blocker", "key.pem")

// Path to the encrypted aes key
var aesKeyPath = filepath.Join(os.TempDir(), "blocker")

var aesKeyName = "%s.key"

// The key to be used to encrypt and decrypt when using RSA encryption
var RsaEncryptionChipher RsaChipher

// Structure for encryption chipher
type RsaChipher struct {
	PrivateKey     *rsa.PrivateKey
	PrivateKeyPath string
	PublicKey      *rsa.PublicKey
	PublicKeyPath  string
}

// Structure to hold unencrypted AES key
type AesKey struct {
	key []byte
}

func init() {
	LoadOrGenerateRsaKey()
}

// Load or Generate a RSA certiciate
func LoadOrGenerateRsaKey() {

	// Read key
	keyBytes, err := ioutil.ReadFile(KeyPath)
	if err == nil {
		// Get private key
		block, _ := pem.Decode(keyBytes)
		privatekey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

		// Set object
		RsaEncryptionChipher = RsaChipher{privatekey, KeyPath, &privatekey.PublicKey, CertifcatePath}

		// We are done
		return
	}

	// No load of existing key.  Generate a new one.
	GenerateRsaKey()
}

// Generate a new key
func GenerateRsaKey() {

	depositoryDir := filepath.Join(os.TempDir(), "blocker")

	err := os.Mkdir(depositoryDir, 0777)
	if err != nil && !os.IsExist(err) {
		panic("Unable to create directory: " + err.Error())
	}

	// Generate a 256 bit private key for use with the encryption
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   "Blocker Encryption Master Key",
			Organization: []string{"Inflatablewoman's CA"},
		},
		NotBefore: now.Add(-5 * time.Minute).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(), // valid for 1 year.

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return
	}

	certOut, err := os.Create(CertifcatePath)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
		return
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written cert.pem\n")

	keyOut, err := os.OpenFile(KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Print("failed to open key.pem for writing:", err)
		return
	}

	marashelledPrivateKeyBytes := x509.MarshalPKCS1PrivateKey(priv)

	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: marashelledPrivateKeyBytes})
	keyOut.Close()

	log.Print("Wrote Certificate to disk.")

	// Now set object
	RsaEncryptionChipher = RsaChipher{priv, KeyPath, &priv.PublicKey, CertifcatePath}
}

// Encrypt data using RSA and a public key
func RsaEncrypt(bytesToEncrypt []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, RsaEncryptionChipher.PublicKey, bytesToEncrypt)
}

// Decrypt data using RSA and a private key
func RsaDecrypt(encryptedBytes []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, RsaEncryptionChipher.PrivateKey, encryptedBytes)
}

// Create a new Aes Secret
func GenerateAesSecret() []byte {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	return key
}

// DeleteAesSecret - Remove a key if not needed
func DeleteAesSecret(hash string) {
	os.Remove(GetAesSecretPath(hash))
}

// Get the AES secret to be used for encryption
func GetAesSecret(hash string) (AesKey, error) {
	// Read key
	keyBytes, err := ioutil.ReadFile(GetAesSecretPath(hash))
	if err == nil {
		key, _ := RsaDecrypt(keyBytes)
		return AesKey{key}, nil
	}

	// Create new Aes Secret
	newAesKey := GenerateAesSecret()

	// Encrypt the key for later use
	encryptedKey, err := RsaEncrypt(newAesKey)
	if err != nil {
		log.Println(fmt.Sprintf("Error writing file : %v", err))
		return AesKey{}, err
	}

	// Save encrypted key to disk
	err = ioutil.WriteFile(GetAesSecretPath(hash), encryptedKey, 0644)
	if err != nil {
		log.Println(fmt.Sprintf("Error writing file : %v", err))
		return AesKey{}, err
	}

	return AesKey{newAesKey}, nil
}

// GetAesSecretPath - Will return a key name for a hash
func GetAesSecretPath(hash string) string {
	return filepath.Join(aesKeyPath, fmt.Sprintf(aesKeyName, hash))
}

// Hex to bytes
func hex2Bytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}

// Bytes to hex
func encodeHex(bytes []byte) string {
	return fmt.Sprintf("%x", bytes)
}

// Encrpyt data using AES with the CFB chipher mode
func AesCfbDecrypt(encryptedBytes []byte, hash string) ([]byte, error) {
	// Get the key for this hash
	aesEncryptionKey, err := GetAesSecret(hash)
	if err != nil {
		return nil, err
	}

	return AesDecrypt(encryptedBytes, aesEncryptionKey.key)
}

// Encrpyt data using AES with the CFB chipher mode
func AesDecrypt(encryptedBytes []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(encryptedBytes) < aes.BlockSize {
		return nil, errors.New("Data to encrypt is too small")
	}
	iv := encryptedBytes[:aes.BlockSize]
	encryptedBytes = encryptedBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(encryptedBytes, encryptedBytes)
	// fmt.Printf("%s", ciphertext)
	// Output: some plaintext

	return encryptedBytes, nil
}

// Encrpyt data using AES with the CFB chipher mode
func AesCfbEncrypt(bytesToEncrypt []byte, hash string) ([]byte, error) {
	// key := []byte("a very very very very secret key") // 32 bytes
	aesEncryptionKey, err := GetAesSecret(hash)
	if err != nil {
		return nil, err
	}

	return AesEncrypt(bytesToEncrypt, aesEncryptionKey.key)
}

// Encrpyt data using AES with the CFB chipher mode
func AesEncrypt(bytesToEncrypt []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(bytesToEncrypt))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], bytesToEncrypt)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.
	return ciphertext, nil
}

// GetHmac256 will generate a HMAC hash encoded to base64
func GetHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
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
