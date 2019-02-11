package kms

import (
	"crypto/aes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/miekg/pkcs11"
)

// HSMMasterKeyProvider is an implementation of aquiring a MASTER key using a connection to a Hardware Security Module
type HSMMasterKeyProvider struct {
}

// NewHSMMasterKeyProvider
func NewHSMMasterKeyProvider() (HSMMasterKeyProvider, error) {
	// Ensure our config is ok...
	SetHSMMasterKeyProviderConfig()

	return HSMMasterKeyProvider{}, nil
}

// SetConfig will check any required settings for this crypto-provider
func SetHSMMasterKeyProviderConfig() {
	envFiles := []string{"GOKMS_HSM_LIB"}

	providerConfig := map[string]string{
		"GOKMS_HSM_LIB":       "",
		"GOKMS_HSM_SLOT":      "0",
		"GOKMS_HSM_AES_KEYID": "",
		// "GOKMS_HSM_SLOT_PASSWORD": "",  // This can be skipped, if the TOKEN does not require a password.
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

// GetKey will return the decrypted master key
func (mkp HSMMasterKeyProvider) GetKey() ([]byte, error) {

	// Set up pkcs11

	log.Printf("Using HSM Lib: %v", Config["GOKMS_HSM_LIB"])

	p := pkcs11.New(Config["GOKMS_HSM_LIB"])
	if p == nil {
		Exit("Failed to init lib", 2)
	}

	if err := p.Initialize(); err != nil {
		Exit(fmt.Sprintf("Initialize() failed %s\n", err), 2)
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	log.Printf("Using %v %v %v.%v", info.ManufacturerID, info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)

	slots, err := p.GetSlotList(true)
	if err != nil {
		Exit(fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	log.Printf("We have got %v slots", len(slots))
	if len(slots) == 0 {
		Exit("No HSM slots...", 2)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		Exit(fmt.Sprintf("OpenSession() failed %s\n", err), 2)
	}

	// Perhaps the HSM requires no pin
	if Config["GOKMS_HSM_SLOT_PIN"] != "" {
		err = p.Login(session, pkcs11.CKU_USER, Config["GOKMS_HSM_SLOT_PIN"])
		if err != nil {
			Exit(fmt.Sprintf("Login() failed %s\n", err), 2)
		}
		defer p.Logout(session)
	}

	defer p.Destroy()
	defer p.Finalize()
	defer p.CloseSession(session)

	// Locate desired key from the HSM

	log.Printf("Looking for hsm key: %v", Config["GOKMS_HSM_AES_KEYID"])

	// Create search index
	keySearch := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, Config["GOKMS_HSM_AES_KEYID"])}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		Exit(fmt.Sprintf("FindObjectsInit() failed %s\n", err), 2)
	}

	// Find the object
	obj, b, err := p.FindObjects(session, 1)
	if err != nil {
		Exit(fmt.Sprintf("FindObjects() failed %s %v\n", err, b), 2)
	}
	if err := p.FindObjectsFinal(session); err != nil {
		Exit(fmt.Sprintf("FindObjectsFinal() failed %s\n", err), 2)
	}

	// Do we already have a master key written to disk?
	keyPath := filepath.Join(Config["GOKMS_KSMC_PATH"], "hsm.master")

	log.Printf("Looking for mk_hsm key: %v", keyPath)

	// Can we use the key?
	_, err = os.Stat(keyPath)
	if err == nil {
		// Read encrypted key from disk
		encryptedKey, err := ioutil.ReadFile(keyPath)
		if err != nil {
			Exit(fmt.Sprintf("ReadFile() failed %s\n", err), 2)
		}

		// Extract iv from encrypted key
		iv := encryptedKey[:aes.BlockSize]

		// Get the actual encrypted data
		encryptedData := encryptedKey[aes.BlockSize:]

		err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, obj[0])
		if err != nil {
			Exit(fmt.Sprintf("DecryptInit() failed %s\n", err), 2)
		}

		// Let's decrypt again
		decryptedData, err := p.Decrypt(session, encryptedData)
		if err != nil {
			Exit(fmt.Sprintf("Decrypt() failed %s\n", err), 2)
		}

		return decryptedData, nil
	}

	// Create new aes key
	masterAesKey, err := p.GenerateRandom(session, 32)
	if err != nil {
		Exit(fmt.Sprintf("GenerateRandom() failed %s\n", err), 2)
	}

	// Create iv
	iv, err := p.GenerateRandom(session, 16)
	if err != nil {
		Exit(fmt.Sprintf("GenerateRandom() failed %s\n", err), 2)
	}

	// Set up encryption
	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		Exit(fmt.Sprintf("AES EncryptInit() failed %s\n", err), 2)
	}

	encryptedData, err := p.Encrypt(session, masterAesKey)
	if err != nil {
		Exit(fmt.Sprintf("Encrypt() failed %s\n", err), 2)
	}

	// Create envelope
	encryptedKey := append(iv, encryptedData...)

	// Store key on disk
	err = ioutil.WriteFile(keyPath, encryptedKey, 0600)
	if err != nil {
		Exit(fmt.Sprintf("WriteFile() failed %s\n", err), 2)
	}

	return masterAesKey, nil
}

/*  HSM - PKCS11 - Play ground code
func TestGetInfo(t *testing.T) {
	p := New("/opt/nfast/toolkits/pkcs11/libcknfast.so")
	if p == nil {
		log.Printf("Failed to init lib", 2)
	}

	if err := p.Initialize(); err != nil {
		log.Printf(fmt.Sprintf("Initialize() failed %s\n", err), 2)
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	log.Printf("Using %v %v %v.%v", info.ManufacturerID, info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)

	slots, err := p.GetSlotList(true)
	if err != nil {
		log.Printf(fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	log.Printf("We have got %v slots", len(slots))
	if len(slots) == 0 {
		log.Printf("No HSM slots...", 2)
	}

	slotInfo, err := p.GetSlotInfo(slots[0])
	if err != nil {
		log.Printf(fmt.Sprintf("GetSlotList() failed %s\n", err), 2)
	}

	log.Printf("Slot 0 Description: %v", slotInfo.SlotDescription)

	/*mechanisms, err := p.GetMechanismList(slots[0])
	if err != nil {
		panic(fmt.Sprintf("GetMechanismList() failed %s\n", err))
	}
	for i, m := range mechanisms {
		log.Printf("Mechanism %d, ID %d, Param %d", i, m.Mechanism, m.Parameter)
	}* /

	tokenInfo, err := p.GetTokenInfo(slots[0])
	if err != nil {
		panic(fmt.Sprintf("GetTokenInfo() failed %s\n", err))
	}

	log.Printf("Token Info.Label: %v ", tokenInfo.Label)
	log.Printf("Token Info.FirmwareVersion: %v ", tokenInfo.FirmwareVersion)
	log.Printf("Token Info.ManufacturerID: %v ", tokenInfo.ManufacturerID)
	log.Printf("Token Info.SerialNumber: %v ", tokenInfo.SerialNumber)
	log.Printf("Token Info.MaxPinLen: %v ", tokenInfo.MaxPinLen)
	log.Printf("Token Info.Model: %v ", tokenInfo.Model)
	log.Printf("Token Info.MinPinLen: %v ", tokenInfo.MinPinLen)
	log.Printf("Token Info.HardwareVersion: %v ", tokenInfo.HardwareVersion)
	log.Printf("Token Info.MaxSessionCount: %v ", tokenInfo.MaxSessionCount)

	session, err := p.OpenSession(slots[0], CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		panic(fmt.Sprintf("OpenSession() failed %s\n", err))
	}

	defer p.Logout(session)
	defer p.CloseSession(session)
	defer p.Finalize()
	defer p.Destroy()

	/*err = p.Login(session, 0, "")
	if err != nil {
		panic(fmt.Sprintf("Login() failed %s\n", err))
	}* /

	// Create search index
	keySearch := []*Attribute{NewAttribute(CKA_LABEL, "GO-KMS Crypto Key")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("FindObjectsInit() failed %s\n", err))
	}

	// Find the object
	obj, b, err := p.FindObjects(session, 2)
	if err != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if err := p.FindObjectsFinal(session); err != nil {
		panic(fmt.Sprintf("FindObjectsFinal() failed %s\n", err))
	}

	log.Printf("Found ojects: %v ", len(obj))

	var pubKey ObjectHandle
	var privKey ObjectHandle

	for i, key := range obj {
		log.Printf("Looking at item %v:", i)
		search := []*Attribute{
			NewAttribute(CKA_LABEL, nil),
			//NewAttribute(CKA_ENCRYPT, nil),
			//NewAttribute(CKA_VALUE_LEN, nil),
			NewAttribute(CKA_CLASS, nil),
		}
		// ObjectHandle two is the public key
		attr, err := p.GetAttributeValue(session, key, search)
		if err != nil {
			panic(fmt.Sprintf("GetAttributeValue() failed %s\n", err))
		}
		for i, a := range attr {
			// Found public key
			if a.Type == CKA_CLASS && bytes.Equal(a.Value, []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
				pubKey = key
			}

			// Found private key
			if a.Type == CKA_CLASS && bytes.Equal(a.Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}) {
				privKey = key
			}

			if a.Type == CKA_LABEL {
				log.Printf("Attr %d, type %d, valuelen %d, value %v", i, a.Type, len(a.Value), string(a.Value))
			} else {
				log.Printf("Attr %d, type %d, value %v", i, a.Type, a.Value)

			}
		}
	}

	log.Printf("Public Key: %v", pubKey)
	log.Printf("Priv Key: %v", privKey)

	err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS, nil)}, pubKey)

	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	data := []byte("There is nothing to fear but fear itself....")

	log.Printf("Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err := p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("Result: %v len: %v ", string(encryptedData), len(encryptedData))

	err = p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS, nil)}, privKey)
	if err != nil {
		panic(fmt.Sprintf("DecryptInit() failed %s\n", err))
	}

	// Let's decrypt again
	decryptedData, err := p.Decrypt(session, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	log.Printf("Decrypted Data: %v len: %v ", string(decryptedData), len(decryptedData))

	// Create search index
	keySearch = []*Attribute{NewAttribute(CKA_LABEL, "My New AES Key")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("FindObjectsInit() failed %s\n", err))
	}

	// Find the object
	obj, b, err = p.FindObjects(session, 2)
	if err != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if err = p.FindObjectsFinal(session); err != nil {
		panic(fmt.Sprintf("FindObjectsFinal() failed %s\n", err))
	}

	log.Printf("Found ojects: %v ", len(obj))

	iv, err := p.GenerateRandom(session, 16)
	if err != nil {
		panic(fmt.Sprintf("GenerateRandom() failed %s\n", err))
	}

	log.Printf("IV: %v", iv)

	// Set up encryption
	err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		panic(fmt.Sprintf("AES EncryptInit() failed %s\n", err))
	}

	log.Printf("Key Inited %v ", obj[0])

	data = []byte("Would the real slim shady please stand up!")

	log.Printf("Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err = p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("AES Result: %v len: %v ", string(encryptedData), len(encryptedData))

	err = p.DecryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC_PAD, iv)}, obj[0])
	if err != nil {
		panic(fmt.Sprintf("DecryptInit() failed %s\n", err))
	}

	// Let's decrypt again
	decryptedData, err = p.Decrypt(session, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	log.Printf("AES Decrypted Data: %v len: %v ", string(decryptedData), len(decryptedData))

	/ *publicKeyTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PUBLIC_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_PUBLIC_EXPONENT, []byte{3}),
		NewAttribute(CKA_MODULUS_BITS, 4096),
		NewAttribute(CKA_LABEL, "Blocker_RSA4096_PubKey"),
	}
	privateKeyTemplate := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_KEY_TYPE, CKK_RSA),
		NewAttribute(CKA_TOKEN, true),
		NewAttribute(CKA_PRIVATE, true),
		NewAttribute(CKA_SIGN, true),
		NewAttribute(CKA_LABEL, "Blocker_RSA4096_PrivKey"),
	}

	pub, priv, err := p.GenerateKeyPair(session, []*Mechanism{NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKeyPair() failed %s\n", err))
	}

	log.Printf("Public Key: %v", pub)
	log.Printf("Priv Key: %v", priv)*/

/*iv := []byte("01020304050607081122334455667788")

// Set up encryption
err = p.EncryptInit(session, []*Mechanism{NewMechanism(CKM_AES_CBC, iv)}, obj[0])
if err != nil {
	panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
}

log.Printf("Key Inited %v ", obj[0])

data := []byte("this is a string")

log.Printf("Encrypt data: %v len: %v ", data, len(data))
encryptedData, err := p.Encrypt(session, data)
if err != nil {
	panic(fmt.Sprintf("Encrypt() failed %s\n", err))
}

log.Printf("Result: %v len: %v ", encryptedData, len(encryptedData))*/

/*aesKeyTemplate := []*Attribute{
	NewAttribute(CKA_LABEL, "Create AES Encryption Key"),
	NewAttribute(CKA_CLASS, CKO_SECRET_KEY),
	NewAttribute(CKA_KEY_TYPE, CKK_AES),
	NewAttribute(CKA_ENCRYPT, true),
	NewAttribute(CKA_TOKEN, true),
	NewAttribute(CKA_VALUE_LEN, 80),
	NewAttribute(CKA_VALUE, 80),
}

aesKey, err := p.CreateObject(session, aesKeyTemplate)
if err != nil {
	panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
}

log.Printf("Key Created %v ", aesKey)*/

/*err = p.Login(session, CKU_USER, "")
	if err != nil {
		log.Printf(fmt.Sprintf("Login() failed %s\n", err), 2)
	}* /
}
*/
