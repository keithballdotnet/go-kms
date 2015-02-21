package kms

import (
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
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
var CertifcatePath = filepath.Join(os.TempDir(), "go-kms", "cert.pem")

// Path to the private key
var KeyPath = filepath.Join(os.TempDir(), "go-kms", "key.pem")

// Path to the encrypted aes key
var aesKeyPath = filepath.Join(os.TempDir(), "go-kms")

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

	depositoryDir := filepath.Join(os.TempDir(), "go-kms")

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
			CommonName:   "Go-KMS Encryption Master Key",
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

// AesGCMEncrypt Encrypt data using AES with the GCM chipher mode (Gives Confidentiality and Authenticity)
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

// AesGCMDecrypt Decrypt data using AES with the GCM chipher mode (Gives Confidentiality and Authenticity)
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

// Encrpyt data using AES with the CFB chipher mode
func AesCFBDecrypt(ciphertext []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Data to decrypt is too small")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Encrpyt data using AES with the CFB chipher mode
func AesCFBEncrypt(plaintext []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

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
