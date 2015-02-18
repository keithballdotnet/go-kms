package kms

import (
	"fmt"
	// "io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// KMSCryptoProvider is an implementation of encryption using a local storage
type KMSCryptoProvider struct {
	userkey []byte
}

// NewKMSCryptoProvider
func NewKMSCryptoProvider() (KMSCryptoProvider, error) {

	log.Println("Using KMS crypto provider...")

	// Ensure our config is ok...
	SetKMSCryptoConfig()

	log.Printf("KSM Crypto Path: %v", Config["GOKMS_KSMC_PATH"])

	// Check path
	_, err := os.Stat(Config["GOKMS_KSMC_PATH"])
	if err != nil {
		// Ensure key path exists
		err := os.Mkdir(Config["GOKMS_KSMC_PATH"], 0777)
		if err != nil && !os.IsExist(err) {
			Exit(fmt.Sprintf("Can't use directory %s: %v", Config["GOKMS_KSMC_PATH"], err), 2)
		}
	}

	// Derive key from pass phrase
	if len(Config["GOKMS_KSMC_PASSPHRASE"]) < 10 {
		Exit(fmt.Sprintf("The pass phrase must be at least 10 characters long is only %v characters", len(Config["GOKMS_KSMC_PASSPHRASE"])), 2)
	}

	// Derive master key from given pass phrase
	aesKey := DeriveAESKey(Config["GOKMS_KSMC_PASSPHRASE"], []byte{})

	return KMSCryptoProvider{userkey: aesKey}, nil
}

// SetKMSCryptoConfig will check any required settings for this crypto-provider
func SetKMSCryptoConfig() {
	envFiles := []string{}

	providerConfig := map[string]string{
		"GOKMS_KSMC_PATH":       filepath.Join(os.TempDir(), "go-kms"),
		"GOKMS_KSMC_PASSPHRASE": "",
	}

	// Load all Environments variables
	for k, _ := range providerConfig {

		// Set default value...
		Config[k] = providerConfig[k]

		// Set env setting
		if os.Getenv(k) != "" {
			Config[k] = os.Getenv(k)
		}
	}
	// All variable MUST have a value but we can not verify the variable content
	for k, _ := range providerConfig {
		if Config[k] == "" {
			Exit(fmt.Sprintf("Problem with %s", k), 2)
		}
	}

	// Check file exists
	for _, v := range envFiles {
		_, err := os.Stat(Config[v])
		if err != nil {
			Exit(fmt.Sprintf("%s %s", v, err.Error()), 2)
		}
	}

	return
}

// FindKey from the the HMS store
func (cp KMSCryptoProvider) FindKey(KeyID string) ([]byte, error) {

	// User the master key for all encryption now.
	return cp.userkey, nil

	// Create path to key
	/*keyPath := filepath.Join(Config["GOKMS_KSMC_PATH"], KeyID, ".key")

	// Read encrypted key from disk
	encryptedKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Printf("FindKey() failed %s\n", err)
		return nil, err
	}

	// decrypt the key with the users derived key
	return AesDecrypt(encryptedKey, cp.userkey)*/
}

// Encrypt will encrypt the data using the HSM
func (cp KMSCryptoProvider) Encrypt(data []byte, KeyID string) ([]byte, error) {

	key, err := cp.FindKey(KeyID)
	if err != nil {
		log.Printf("Encrypt - FindKey() failed %s\n", err)
		return nil, err
	}

	encryptedData, err := AesEncrypt(data, key)
	if err != nil {
		log.Printf("Encrypt - AesEncrypt() failed %s\n", err)
		return nil, err
	}

	log.Printf("Result: %v len: %v ", string(encryptedData), len(encryptedData))

	return encryptedData, nil
}

// Decrypt will decrypt the data using the HSM
func (cp KMSCryptoProvider) Decrypt(data []byte, KeyID string) ([]byte, error) {

	key, err := cp.FindKey(KeyID)
	if err != nil {
		log.Printf("FindKey() failed %s\n", err)
		return nil, err
	}

	// Let's decrypt again
	decryptedData, err := AesDecrypt(data, key)
	if err != nil {
		log.Printf("Decrypt() failed %s\n", err)
		return nil, err
	}

	log.Printf("Result: %v len: %v ", string(decryptedData), len(decryptedData))

	return decryptedData, nil
}
