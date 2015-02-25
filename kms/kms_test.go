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

	os.Setenv("GOKMS_KSMC_PATH", c.MkDir())

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

func (s *KMSSuite) TestHSMMasterKeyProvider(c *C) {

	c.Skip("HSM must be set up for this test to work")

	os.Setenv("GOKMS_HSM_LIB", "/opt/nfast/toolkits/pkcs11/libcknfast.so")
	os.Setenv("GOKMS_HSM_SLOT", "0")
	os.Setenv("GOKMS_HSM_AES_KEYID", "My New AES Key")
	os.Setenv("GOKMS_KSMC_PATH", "/home/keithball/Documents/tokens")
	Config["GOKMS_KSMC_PATH"] = "/home/keithball/Documents/tokens"
	// Ensure we actually match the interface
	var mkp MasterKeyProvider
	mkp, err := NewHSMMasterKeyProvider()

	// Get key
	key, err := mkp.GetKey()

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Ensure key is 32 bytes
	c.Assert(len(key) == 32, IsTrue)

	fmt.Printf("Key is: %v %v", key, string(key))
}

func (s *KMSSuite) TestAuthenticationKeyCreation(c *C) {
	Config["GOKMS_AUTH_KEY"] = c.MkDir() + "auth.key"

	SetupAuthenticationKey()

	// Reset test Shared Key
	SharedKey = "e7yflbeeid26rredmwtbiyzxijzak6altcnrsi4yol2f5sexbgdwevlpgosfoeyy"
}

func (s *KMSSuite) TestCreateKeyThenGetKeyListKeysAndCheckKeyIsThere(c *C) {
	desc := "A new key description!"

	keyMetadata, err := KmsCrypto.CreateKey(desc)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	c.Assert(desc == keyMetadata.Description, IsTrue)
	c.Assert(keyMetadata.Enabled, IsTrue)
	c.Assert(keyMetadata.KeyID != "", IsTrue)

	key, err := KmsCrypto.GetKey(keyMetadata.KeyID)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Ensure key is 32 bytes
	c.Assert(len(key.AESKey) == 32, IsTrue)

	c.Assert(key.KeyMetadata.Description == desc, IsTrue)

	c.Assert(key.KeyMetadata.Enabled, IsTrue)

	keyList, err := KmsCrypto.ListKeys()

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	keyFoundInList := false

	for _, k := range keyList {
		if k.KeyID == keyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}

	c.Assert(keyFoundInList, IsTrue)
}

func (s *KMSSuite) TestRESTInterfaceFunctions(c *C) {

	// Create temporary store for keys during test
	Config["GOKMS_KSMC_PATH"] = c.MkDir()

	context := Context{UserAgent: "KMS Test Agent"}

	u := url.URL{Path: "/api/v1/go-kms/createkey"}
	r := http.Request{Header: http.Header{"accept": {"application/json"}}}
	request := SetAuth(&r, "POST", u.Path)

	description := "Test Encryption Key"

	createKeyRequest := CreateKeyRequest{Description: description}

	status, _, createKeyResponse, err := createKeyHandler(&u, request.Header, &createKeyRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure the key is enabled
	c.Assert(createKeyResponse.KeyMetadata.Enabled, IsTrue)

	// Check the description is correct
	c.Assert(createKeyResponse.KeyMetadata.Description == description, IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/listkeys"}
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "POST", u.Path)

	listKeysRequest := ListKeysRequest{}

	status, _, listKeysResponse, err := listKeysHandler(&u, request.Header, &listKeysRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Assert the key is listed
	keyFoundInList := false

	for _, k := range listKeysResponse.KeyMetadata {
		if k.KeyID == createKeyResponse.KeyMetadata.KeyID {
			keyFoundInList = true
			break
		}
	}

	c.Assert(keyFoundInList, IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/generatedatakey"}
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "POST", u.Path)

	dataKeyRequest := GenerateDataKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

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

	decryptRequest := DecryptRequest{CiphertextBlob: dataKeyResponse.CiphertextBlob}

	status, _, decryptResponse, err := decryptHandler(&u, request.Header, &decryptRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Want a 32 byte AES Key
	c.Assert(len(decryptResponse.Plaintext) == 32, IsTrue, Commentf("Key not correct length wanted 32 got %v", len(dataKeyResponse.Plaintext)))

	// Ensure decrypted key is the same as the key we go via plain text
	c.Assert(bytes.Equal(decryptResponse.Plaintext, aesKey), IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/encrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	somePlaintext := []byte("Kaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahn!")

	encryptRequest := EncryptRequest{KeyID: createKeyResponse.KeyMetadata.KeyID, Plaintext: somePlaintext}

	status, _, encryptResponse, err := encryptHandler(&u, request.Header, &encryptRequest, &context)

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	// Status
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure we have some data
	c.Assert(len(encryptResponse.CiphertextBlob) > 0, IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/decrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	decryptRequest = DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure decrypted key is the same as the key we go via plain text
	c.Assert(bytes.Equal(decryptResponse.Plaintext, somePlaintext), IsTrue)

	// Disable the key and try to decrypt again

	u = url.URL{Path: "/api/v1/go-kms/disablekey"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	disableKeyRequest := DisableKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, disableKeyResponse, err := disableKeyHandler(&u, request.Header, &disableKeyRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	c.Assert(disableKeyResponse.KeyMetadata.Enabled, IsFalse)

	u = url.URL{Path: "/api/v1/go-kms/decrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	decryptRequest = DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	c.Assert(status == http.StatusOK, IsFalse)

	u = url.URL{Path: "/api/v1/go-kms/enablekey"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	enableKeyRequest := EnableKeyRequest{KeyID: createKeyResponse.KeyMetadata.KeyID}

	status, _, enableKeyResponse, err := enableKeyHandler(&u, request.Header, &enableKeyRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	c.Assert(enableKeyResponse.KeyMetadata.Enabled, IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/decrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	decryptRequest = DecryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure decrypted key is the same as the key we go via plain text
	c.Assert(bytes.Equal(decryptResponse.Plaintext, somePlaintext), IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/createkey"}
	r = http.Request{Header: http.Header{"accept": {"application/json"}}}
	request = SetAuth(&r, "POST", u.Path)

	description2 := "II Test Encryption Key"

	createKeyRequest2 := CreateKeyRequest{Description: description2}

	status, _, createKeyResponse2, err := createKeyHandler(&u, request.Header, &createKeyRequest2, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure the key is enabled
	c.Assert(createKeyResponse2.KeyMetadata.Enabled, IsTrue)

	// Check the description is correct
	c.Assert(createKeyResponse2.KeyMetadata.Description == description2, IsTrue)

	u = url.URL{Path: "/api/v1/go-kms/reencrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	reEncryptRequest := ReEncryptRequest{CiphertextBlob: encryptResponse.CiphertextBlob, DestinationKeyID: createKeyResponse2.KeyMetadata.KeyID}

	status, _, reEncryptResponse, err := reEncryptHandler(&u, request.Header, &reEncryptRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure the key was encrypted with the original key
	c.Assert(reEncryptResponse.SourceKeyID == createKeyResponse.KeyMetadata.KeyID, IsTrue)

	// Ensure data is now encrypted with the new key
	c.Assert(reEncryptResponse.KeyID == createKeyResponse2.KeyMetadata.KeyID, IsTrue)

	// Ensure that the encrypted data has changed
	c.Assert(bytes.Equal(reEncryptResponse.CiphertextBlob, encryptResponse.CiphertextBlob), IsFalse)

	u = url.URL{Path: "/api/v1/go-kms/decrypt"}

	r = http.Request{Header: http.Header{"accept": {"application/json"}}}

	request = SetAuth(&r, "POST", u.Path)

	decryptRequest = DecryptRequest{CiphertextBlob: reEncryptResponse.CiphertextBlob}

	status, _, decryptResponse, err = decryptHandler(&u, request.Header, &decryptRequest, &context)

	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))
	c.Assert(status == http.StatusOK, IsTrue, Commentf("Incorrect return status: wanted %v got %v", http.StatusOK, status))

	// Ensure decrypted key is the same as the key we go via plain text
	c.Assert(bytes.Equal(decryptResponse.Plaintext, somePlaintext), IsTrue)

}

func (s *KMSSuite) TestHMSEncryptDecrypt(c *C) {

	c.Skip("No HSM test")

	data := KmsCrypto.GenerateAesKey()

	fmt.Printf("Encrypt data: %v len: %v ", string(data), len(data))

	encryptedData, err := KmsCrypto.Encrypt(data, "Blocker_RSA4096_PubKey")

	fmt.Println("HSM encrypted bytes: " + string(encryptedData))

	// No error
	c.Assert(err == nil, IsTrue, Commentf("Got error: %v", err))

	decryptedData, _, err := KmsCrypto.Decrypt(encryptedData)

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

func (s *KMSSuite) TestAesGCMCrypto(c *C) {

	encryptString := "I once had a girl, or should I say, she once had me."

	bytesToEncrypt := []byte(encryptString)

	fmt.Println("GCM bytes to encrypt: " + string(bytesToEncrypt))

	aesKey := KmsCrypto.GenerateAesKey()

	encryptedBytes, err := AesGCMEncrypt(bytesToEncrypt, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("GCM encrypted bytes: " + string(encryptedBytes))

	unencryptedBytes, err := AesGCMDecrypt(encryptedBytes, aesKey)

	if err != nil {
		fmt.Println("Got error: " + err.Error())
	}

	// No error
	c.Assert(err == nil, IsTrue)

	fmt.Println("GCM Unencrypted bytes: " + string(unencryptedBytes))

	c.Assert(bytes.Equal(bytesToEncrypt, unencryptedBytes), IsTrue)
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

func TestGetRandomNumber(t *testing.T) {

	// Lets get a 6 digit number
	random := GetRandomInt(100000, 999999)

	if random < 100000 || random > 999999 {
		t.Fatal("Number is outside of desired range")
	}

	fmt.Printf("Random is: %v\n", random)
}

func TestRandomSecret(t *testing.T) {

	secret := RandomSecret(0)

	if secret == "" {
		t.Fatal("Secret is empty")
	}

	if len(secret) != 16 {
		t.Fatal("Secret is too short by default")
	}

	fmt.Printf("Random is: %v\n", secret)
}

func Test32CharRandomSecret(t *testing.T) {

	secret := RandomSecret(40)

	fmt.Printf("Random is: %v Len: %v\n", secret, len(secret))

	if secret == "" {
		t.Fatal("Secret is empty")
	}

	if len(secret) != 64 {
		t.Fatal("Secret is not 64")
	}

	fmt.Printf("Random is: %v\n", secret)
}
