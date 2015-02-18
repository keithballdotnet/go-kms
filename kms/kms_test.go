package kms

import (
	"bytes"
	"fmt"
	. "github.com/Inflatablewoman/go-kms/gocheck2"
	. "gopkg.in/check.v1"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func Test(t *testing.T) {
	TestingT(t)
}

type KMSSuite struct {
}

var _ = Suite(&KMSSuite{})

func (s *KMSSuite) SetUpSuite(c *C) {

	os.Setenv("GOKMS_HSM_SLOT_PASSWORD", "1234")

	os.Setenv("GOKMS_KSMC_PASSPHRASE", "A long passphrase that will be used to generate the master key")

	InitConfig()

	// Create provider
	KmsCrypto, _ = NewKMSCryptoProvider()

	// Shared Key
	SharedKey = "e7yflbeeid26rredmwtbiyzxijzak6altcnrsi4yol2f5sexbgdwevlpgosfoeyy"
}

// Test down the suite
func (s *KMSSuite) TearDownSuite(c *C) {
}

// SetAuth will set kms auth headers
func SetAuth(request *http.Request, method string, resource string) *http.Request {

	date := time.Now().UTC().Format(time.RFC1123) // UTC time
	request.Header.Add("x-kms-date", date)

	authRequestKey := fmt.Sprintf("%s\n%s\n%s", method, date, resource)

	hmac := GetHmac256(authRequestKey, SharedKey)

	//fmt.Printf("SharedKey: %s HMAC: %s RequestKey: \n%s\n", SharedKey, hmac, authRequestKey)

	request.Header.Add("Authorization", hmac)

	return request
}

func (s *KMSSuite) TestGenerateDataKeyAndDecrypt(c *C) {

	u := url.URL{Path: "/api/v1/go-kms/generatedatakey"}

	r := http.Request{Header: http.Header{"accept": {"application/json"}}}

	request := SetAuth(&r, "POST", u.Path)
	context := Context{UserAgent: "Test"}

	dataKeyRequest := GenerateDataKeyRequest{KeyID: "Blocker_RSA4096_PubKey"}

	status, _, dataKeyResponse, err := generateDataKeyHandler(&u, request.Header, &dataKeyRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Want a 32 byte AES Key
	c.Assert(len(dataKeyResponse.Plaintext) == 32, IsTrue, Commentf("Key not correct length wanted 32 got %v", len(dataKeyResponse.Plaintext)))

	aesKey := dataKeyResponse.Plaintext

	// Ensure the data is different
	c.Assert(bytes.Equal(dataKeyResponse.Plaintext, dataKeyResponse.CiphertextBlob), IsFalse)

	u = url.URL{Path: "/api/v1/go-kms/decrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	decryptRequest := DecryptRequest{CiphertextBlob: dataKeyResponse.CiphertextBlob, KeyID: "Blocker_RSA4096_PrivKey"}

	status, _, decryptResponse, err := decryptHandler(&u, request.Header, &decryptRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Want a 32 byte AES Key
	c.Assert(len(decryptResponse.Plaintext) == 32, IsTrue, Commentf("Key not correct length wanted 32 got %v", len(dataKeyResponse.Plaintext)))

	// Ensure decrypted key is the same as the key we go via plain text
	c.Assert(bytes.Equal(decryptResponse.Plaintext, aesKey), IsTrue)
}

func (s *KMSSuite) TestHMSEncryptDecrypt(c *C) {

	data := GenerateAesSecret()

	fmt.Printf("Encrypt data: %v len: %v ", string(data), len(data))

	encryptedData, err := KmsCrypto.Encrypt(data, "Blocker_RSA4096_PubKey")

	fmt.Println("HSM encrypted bytes: " + string(encryptedData))

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	decryptedData, err := KmsCrypto.Decrypt(encryptedData, "Blocker_RSA4096_PrivKey")

	fmt.Println("HSM decrypted bytes: " + string(decryptedData))

	c.Assert(bytes.Equal(data, decryptedData), IsTrue)
}

func (s *KMSSuite) TestGenerateKeyFromPassphrase(c *C) {

	salt := []byte{} //GetSalt(8)

	aesKey := DeriveAESKey("ThisIsAGreatPassphrase", salt)

	fmt.Println("Aes Key from passphrase: " + string(aesKey))

	aesKey2 := DeriveAESKey("ThisIsAGreatPassphrase", salt)

	fmt.Println("Aes Key 2 from passphrase: " + string(aesKey2))

	c.Assert(bytes.Equal(aesKey, aesKey2), IsTrue)

}

func (s *KMSSuite) TestAesCrypto(c *C) {

	encryptString := "a very very very very secret pot"

	bytesToEncrypt := []byte(encryptString)

	fmt.Println("bytes to encrypt: " + string(bytesToEncrypt))

	aesKey := GenerateAesSecret()

	encryptedBytes, err := AesEncrypt(bytesToEncrypt, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("encrypted bytes: " + string(encryptedBytes))

	unencryptedBytes, err := AesDecrypt(encryptedBytes, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("Unencrypted bytes: " + string(unencryptedBytes))

	c.Assert(bytes.Equal(bytesToEncrypt, unencryptedBytes), IsTrue)
}

func (s *KMSSuite) TestRsaCrypto(c *C) {

	encryptString := "a very very very very secret pot"

	bytesToEncrypt := []byte(encryptString)

	fmt.Println("bytes to encrypt: " + string(bytesToEncrypt))

	encryptedBytes, err := RsaEncrypt(bytesToEncrypt)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("encrypted bytes: " + string(encryptedBytes))

	unencryptedBytes, err := RsaDecrypt(encryptedBytes)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("Unencrypted bytes: " + string(unencryptedBytes))

	c.Assert(bytes.Equal(bytesToEncrypt, unencryptedBytes), IsTrue)
}

func (s *KMSSuite) TestGenerateKey(c *C) {

	c.Skip("Not interesting")

	GenerateRsaKey()

	c.Assert(RsaEncryptionChipher.PublicKeyPath == CertifcatePath, IsTrue)
	c.Assert(RsaEncryptionChipher.PrivateKeyPath == KeyPath, IsTrue)

	certInfo, err := os.Stat(CertifcatePath)
	c.Assert(err == nil, IsTrue)
	c.Assert(certInfo.Size() > 0, IsTrue)

	keyInfo, err := os.Stat(KeyPath)
	c.Assert(err == nil, IsTrue)
	c.Assert(keyInfo.Size() > 0, IsTrue)
}

func (s *KMSSuite) TestHMACKey(c *C) {

	expectedHmac := "RvPtP0QB7iIun1ehwheD4YUo7+fYfw7/ywl+HsC5Ddk="

	// The secret key
	secretKey := "e7yflbeeid26rredmwtbiyzxijzak6altcnrsi4yol2f5sexbgdwevlpgosfoeyy"
	method := "COPY"
	//date := time.Now().UTC().Format(time.RFC1123) // UTC time
	//fmt.Printf("Now: %s", date)
	date := "Wed, 28 Jan 2015 10:42:13 UTC"
	resource := "/api/v1/blocker/6f90d707-3b6a-4321-b32c-3c1d37915c1b"

	// Create auth request key
	authRequestKey := fmt.Sprintf("%s\n%s\n%s", method, date, resource)

	hmac := GetHmac256(authRequestKey, secretKey)

	// Test positive.
	c.Assert(expectedHmac == hmac, IsTrue, Commentf("HMAC wrong: %v Got Key %s", expectedHmac, hmac))

	// Test negative.  (Resource and Data in wrong order)
	authRequestKey = fmt.Sprintf("%s\n%s\n%s", method, resource, date)

	hmac = GetHmac256(authRequestKey, secretKey)

	// Test positive.
	c.Assert(expectedHmac != hmac, IsTrue, Commentf("HMAC should be differnt: %v Got Key %s", expectedHmac, hmac))
}
