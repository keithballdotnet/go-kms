package kms

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"os"
)

// Start - Will set up and start the server
func Start() {
	// Get and check config
	initConfig()

	// Start REST endpoint
	StartListener()
}

var Config = map[string]string{
	"GOKMS_AUTH_KEY":          "./files/auth.key",
	"GOKMS_CRYPTO_PROVIDER":   "softhsm2",
	"GOKMS_HOST":              "localhost",
	"GOKMS_PORT":              "8011",
	"GOKMS_SSL_CERT":          "./files/ssl_cert.pem",
	"GOKMS_SSL_KEY":           "./files/ssl_cert.key",
	"GOKMS_HSM_LIB":           "/usr/lib64/pkcs11/libsofthsm2.so",
	"GOKMS_HSM_SLOT":          "",
	"GOKMS_HSM_SLOT_PASSWORD": "",
	"GOKMS_HSM_KEY_LABEL":     "",
	"SOFTHSM2_CONF":           "./files/softhsm2.conf",
}

// initConfig read several Environment variables and based on them initialise the configuration
func initConfig() {
	envFiles := []string{"SOFTHSM2_CONF", "GOKMS_HSM_LIB", "GOKMS_SSL_CERT", "GOKMS_SSL_KEY"}

	// Load all Environments variables
	for k, _ := range Config {
		if os.Getenv(k) != "" {
			Config[k] = os.Getenv(k)
		}
	}
	// All variable MUST have a value but we can not verify the variable content
	for k, _ := range Config {
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
}

// exit will return an error code and the reason to the os
func Exit(messages string, errorCode int) {
	// Exit code and messages based on Nagios plugin return codes (https://nagios-plugins.org/doc/guidelines.html#AEN78)
	var prefix = map[int]string{0: "OK", 1: "Warning", 2: "Critical", 3: "Unknown"}

	// Catch all unknown errorCode and convert them to Unknown
	if errorCode < 0 || errorCode > 3 {
		errorCode = 3
	}

	fmt.Printf("%s %s\n", prefix[errorCode], messages)
	os.Exit(errorCode)
}

func BasicTest() {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM2_CONF", wd+"/softhsm2.conf")

	log.Printf("Set conf to %v", os.Getenv("SOFTHSM2_CONF"))

	p := pkcs11.New("/usr/lib64/pkcs11/libsofthsm2.so")
	if p == nil {
		panic("Failed to init lib")
	}

	if e := p.Initialize(); e != nil {
		panic("init error %s\n" + e.Error())
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	log.Printf("Using %v %v %v.%v", info.ManufacturerID, info.LibraryDescription, info.LibraryVersion.Major, info.LibraryVersion.Minor)

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(fmt.Sprintf("GetSlotList() failed %s\n", err))
	}

	log.Printf("We have got %v slots", len(slots))
	if len(slots) == 0 {
		panic("No slots...")
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	defer p.CloseSession(session)
	if err != nil {
		panic(fmt.Sprintf("OpenSession() failed %s\n", err))
	}

	err = p.Login(session, pkcs11.CKU_USER, "1234")
	defer p.Logout(session)
	if err != nil {
		panic(fmt.Sprintf("Login() failed %s\n", err))
	}

	/*aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, 32),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "My First AES Key"),
	}

	aesKey, err := p.CreateObject(session, aesKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
	}

	log.Printf("Key Created %v ", aesKey)*/

	/*keySearch := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, "My First AES Key")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	obj, b, e := p.FindObjects(session, 1)
	if e != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if e := p.FindObjectsFinal(session); e != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}

	aesKey := obj[0]

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		//pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	}
	// ObjectHandle two is the public key
	attr, err := p.GetAttributeValue(session, aesKey, template)
	if err != nil {
		panic(fmt.Sprintf("GetAttributeValue() failed %s\n", err))
	}
	for i, a := range attr {
		log.Printf("Attr %d, type %d, valuelen %d, value %v", i, a.Type, len(a.Value), string(a.Value))
	}

	// Set up encryption
	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, nil)}, aesKey)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	log.Printf("Key Inited %v ", aesKey)

	data := []byte("this is a string")

	log.Printf("Encrypt data: %v len: %v ", data, len(data))
	encryptedData, err := p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("Result: %v len: %v ", encryptedData, len(encryptedData))*/

	/*keySearch := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyFirstKey")}
	err = p.FindObjectsInit(session, keySearch)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	obj, b, e := p.FindObjects(session, 1)
	if e != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}
	if e := p.FindObjectsFinal(session); e != nil {
		panic(fmt.Sprintf("FindObjects() failed %s %v\n", err, b))
	}

	aesKey := obj[0]

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	}
	// ObjectHandle two is the public key
	attr, err := p.GetAttributeValue(session, aesKey, template)
	if err != nil {
		panic(fmt.Sprintf("GetAttributeValue() failed %s\n", err))
	}
	for i, a := range attr {
		log.Printf("Attr %d, type %d, valuelen %d, value %v", i, a.Type, len(a.Value), string(a.Value))
	}*/

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 4096),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyHardCoreKey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyHardCoreKey"),
	}

	pub, priv, err := p.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKeyPair() failed %s\n", err))
	}

	log.Printf("Public Key: %v", pub)

	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pub)

	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	log.Printf("Key Inited %v ", pub)

	data := []byte("this is a string")

	log.Printf("Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err := p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("Result: %v len: %v ", string(encryptedData), len(encryptedData))

	err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, priv)
	if err != nil {
		panic(fmt.Sprintf("DecryptInit() failed %s\n", err))
	}

	// Let's decrypt again
	decryptedData, err := p.Decrypt(session, encryptedData)
	if err != nil {
		panic(fmt.Sprintf("Decrypt() failed %s\n", err))
	}

	log.Printf("Result: %v len: %v ", string(decryptedData), len(decryptedData))

	/*p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, _ := p.Digest(session, []byte("this is a string"))
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()*/
}
