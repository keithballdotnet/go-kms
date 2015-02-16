package kms

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"os"
)

// Remove this...
var keyHandle pkcs11.ObjectHandle

// NewHMSCryptoProvider is an implementation of encryption using a connection to a Hardware Security Module
type HSMCryptoProvider struct {
	p       *pkcs11.Ctx
	session pkcs11.SessionHandle
}

// NewHMSCryptoProvider
func NewHSMCryptoProvider() (HSMCryptoProvider, error) {

	os.Setenv("SOFTHSM2_CONF", Config["SOFTHSM2_CONF"])

	log.Printf("HSM Lib: %v", Config["GOKMS_HSM_LIB"])
	log.Printf("HSM Conf %v", Config["SOFTHSM2_CONF"])

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

	err = p.Login(session, pkcs11.CKU_USER, Config["GOKMS_HSM_SLOT_PASSWORD"])
	if err != nil {
		Exit(fmt.Sprintf("Login() failed %s\n", err), 2)
	}

	//TODO Clean up.  Based on use count???

	//defer p.Destroy()
	//defer p.Finalize()
	//defer p.Logout(session)
	//defer p.CloseSession(session)

	return HSMCryptoProvider{p: p, session: session}, nil
}

// FindKey from the the HMS store
func (cp HSMCryptoProvider) FindKey(KeyID string) (pkcs11.ObjectHandle, error) {

	// Create search index
	keySearch := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, KeyID)}
	err := cp.p.FindObjectsInit(cp.session, keySearch)
	if err != nil {
		log.Printf("FindObjectsInit() failed %s\n", err)
		return 0, err
	}

	// Find the object
	obj, b, err := cp.p.FindObjects(cp.session, 1)
	if err != nil {
		log.Printf("FindObjects() failed %s %v\n", err, b)
		return 0, err
	}
	if err := cp.p.FindObjectsFinal(cp.session); err != nil {
		log.Printf("FindObjectsFinal() failed %s\n", err)
		return 0, err
	}

	return obj[0], nil
}

// Encrypt will encrypt the data using the HSM
func (cp HSMCryptoProvider) Encrypt(data []byte, KeyID string) ([]byte, error) {

	pub, err := cp.FindKey("Blocker_RSA4096_PubKey")
	if err != nil {
		log.Printf("FindKey() failed %s\n", err)
		return nil, err
	}

	err = cp.p.EncryptInit(cp.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pub)

	if err != nil {
		log.Printf("EncryptInit() failed %s\n", err)
		return nil, err
	}

	log.Printf("Key Inited %v ", pub)

	log.Printf("Encrypt data: %v len: %v ", string(data), len(data))
	encryptedData, err := cp.p.Encrypt(cp.session, data)
	if err != nil {

		log.Printf("Encrypt() failed %s\n", err)
		return nil, err
	}

	log.Printf("Result: %v len: %v ", string(encryptedData), len(encryptedData))

	return encryptedData, nil
}

// Decrypt will decrypt the data using the HSM
func (cp HSMCryptoProvider) Decrypt(data []byte, KeyID string) ([]byte, error) {

	priv, err := cp.FindKey("Blocker_RSA4096_PrivKey")
	if err != nil {
		log.Printf("FindKey() failed %s\n", err)
		return nil, err
	}

	err = cp.p.DecryptInit(cp.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, priv)
	if err != nil {
		log.Printf("DecryptInit() failed %s\n", err)
		return nil, err
	}

	// Let's decrypt again
	decryptedData, err := cp.p.Decrypt(cp.session, data)
	if err != nil {
		log.Printf("Decrypt() failed %s\n", err)
		return nil, err
	}

	log.Printf("Result: %v len: %v ", string(decryptedData), len(decryptedData))

	return decryptedData, nil
}

/*func BasicTest() {

os.Setenv("SOFTHSM2_CONF", "/home/keithball/Documents/go-kms/src/github.com/Inflatablewoman/go-kms/files/softhsm2.conf")

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

search := []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
	//pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	//pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
}
// ObjectHandle two is the public key
attr, err := p.GetAttributeValue(session, aesKey, search)
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

	search := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
	}
	// ObjectHandle two is the public key
	attr, err := p.GetAttributeValue(session, aesKey, search)
	if err != nil {
		panic(fmt.Sprintf("GetAttributeValue() failed %s\n", err))
	}
	for i, a := range attr {
		log.Printf("Attr %d, type %d, valuelen %d, value %v", i, a.Type, len(a.Value), string(a.Value))
	}* /

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 4096),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "Blocker_RSA4096_PubKey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "Blocker_RSA4096_PrivKey"),
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

	/ *p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, _ := p.Digest(session, []byte("this is a string"))
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()* /
}*/
