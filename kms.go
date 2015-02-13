package kms

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
	"os"
)

func BasicTest() {
	wd, _ := os.Getwd()
	os.Setenv("SOFTHSM_CONF", wd+"/softhsm.conf")

	log.Printf("Set conf to %v", os.Getenv("SOFTHSM_CONF"))

	p := pkcs11.New("/usr/lib64/softhsm/libsofthsm.so")
	if p == nil {
		panic("Failed to init lib")
	}

	if e := p.Initialize(); e != nil {
		panic("init error %s\n" + e.Error())
	}

	// What PKS11 info do we get
	info, err := p.GetInfo()

	log.Printf("Using %v %v", info.ManufacturerID, info.LibraryDescription)

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

	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, 16),                 /* KeyLength */
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "My First AES Key"), /* Name of Key */
	}

	aesKey, err := p.CreateObject(session, aesKeyTemplate)
	//aesKey, err := p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, aesKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKey() failed %s\n", err))
	}

	/*publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 1024),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyFirstKey"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyFirstKey"),
	}

	pub, _, err := p.GenerateKeyPair(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		panic(fmt.Sprintf("GenerateKeyPair() failed %s\n", err))
	}

	log.Printf("Public Key: %v", pub)*/

	// Set up encryption
	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, nil)}, aesKey)
	//err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, nil)}, pub)
	if err != nil {
		panic(fmt.Sprintf("EncryptInit() failed %s\n", err))
	}

	data := []byte("this is a string")

	log.Printf("Encrypt data: %v len: %v ", data, len(data))
	encryptedData, err := p.Encrypt(session, data)
	if err != nil {
		panic(fmt.Sprintf("Encrypt() failed %s\n", err))
	}

	log.Printf("Result: %v len: %v ", encryptedData, len(encryptedData))

	/*p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, _ := p.Digest(session, []byte("this is a string"))
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()*/
}
