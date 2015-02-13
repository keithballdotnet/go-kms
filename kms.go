package kms

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"os"
)

func BasicTest() {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM2_CONF", wd+"/softhsm2.conf")

	//os.Setenv("SOFTHSM2_CONF", "/home/keithball/Documents/softhsm/softhsm-2.0.0b2/softhsm.conf")

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
