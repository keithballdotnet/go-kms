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

	session, _ := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	defer p.CloseSession(session)
	p.Login(session, pkcs11.CKU_USER, "1234")
	defer p.Logout(session)
	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, _ := p.Digest(session, []byte("this is a string"))
	for _, d := range hash {
		fmt.Printf("%x", d)
	}
	fmt.Println()
}
