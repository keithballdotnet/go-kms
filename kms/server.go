package kms

import (
	"fmt"
	"github.com/rcrowley/go-tigertonic"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	// This key is used for authentication with the server
	SharedKey = ""
)

// Context information for Marshaled calls
type Context struct {
	UserAgent  string
	RemoteAddr string
}

// StartListener start a HTTP listener
func StartListener() {

	// Set up the auth key
	SetupAuthenticationKey()

	// Set-up API listeners
	mux := tigertonic.NewTrieServeMux()
	mux.Handle("POST", "/api/v1/go-kms/listkeys", tigertonic.If(
		func(r *http.Request) (http.Header, error) {
			tigertonic.Context(r).(*Context).UserAgent = r.UserAgent()
			tigertonic.Context(r).(*Context).RemoteAddr = RequestAddr(r)
			return nil, nil
		},
		tigertonic.Marshaled(listKeysHandler),
	))
	mux.Handle("POST", "/api/v1/go-kms/createkey", tigertonic.If(
		func(r *http.Request) (http.Header, error) {
			tigertonic.Context(r).(*Context).UserAgent = r.UserAgent()
			tigertonic.Context(r).(*Context).RemoteAddr = RequestAddr(r)
			return nil, nil
		},
		tigertonic.Marshaled(createKeyHandler),
	))
	mux.Handle("POST", "/api/v1/go-kms/generatedatakey", tigertonic.If(
		func(r *http.Request) (http.Header, error) {
			tigertonic.Context(r).(*Context).UserAgent = r.UserAgent()
			tigertonic.Context(r).(*Context).RemoteAddr = RequestAddr(r)
			return nil, nil
		},
		tigertonic.Marshaled(generateDataKeyHandler),
	))
	mux.Handle("POST", "/api/v1/go-kms/decrypt", tigertonic.If(
		func(r *http.Request) (http.Header, error) {
			tigertonic.Context(r).(*Context).UserAgent = r.UserAgent()
			tigertonic.Context(r).(*Context).RemoteAddr = RequestAddr(r)
			return nil, nil
		},
		tigertonic.Marshaled(decryptHandler),
	))
	mux.Handle("POST", "/api/v1/go-kms/encrypt", tigertonic.If(
		func(r *http.Request) (http.Header, error) {
			tigertonic.Context(r).(*Context).UserAgent = r.UserAgent()
			tigertonic.Context(r).(*Context).RemoteAddr = RequestAddr(r)
			return nil, nil
		},
		tigertonic.Marshaled(encryptHandler),
	))

	// Log to Console
	server := tigertonic.NewServer(fmt.Sprintf("%s:%s", Config["GOKMS_HOST"], Config["GOKMS_PORT"]), tigertonic.ApacheLogged(mux))
	if err := server.ListenAndServeTLS(Config["GOKMS_SSL_CERT"], Config["GOKMS_SSL_KEY"]); err != nil {
		Exit(fmt.Sprintf("Problem starting server: %v ", err), 2)
	}

}

// SetupAuthenticationKey  - This deals with setting an auth key for the service
func SetupAuthenticationKey() {

	keyPath := Config["GOKMS_AUTH_KEY"]

	// Read the auth key file
	bytes, err := ioutil.ReadFile(keyPath)

	// No file present.  Let's create a key.
	if err != nil && os.IsNotExist(err) {
		newAccessKey := strings.ToLower(RandomSecret(40))
		log.Printf("Generated new Access Key: %s", newAccessKey)
		// Write key to key file
		err := ioutil.WriteFile(keyPath, []byte(newAccessKey), 0644)
		if err != nil {
			Exit("Unable to write shared key file: "+err.Error(), 2)
		}

		// Set the key
		SharedKey = newAccessKey

		// We're done.
		return
	}

	log.Println("Using auth key file...")

	// Get the key
	SharedKey = string(bytes)
}

// CreateKeyRequest
type CreateKeyRequest struct {
	Description string `json:"Description,omitempty"`
}

// CreateKeyResponse
type CreateKeyResponse struct {
	KeyMetadata KeyMetadata `json:"KeyMetadata"`
}

// createKeyHandler will generate a new stored key
func createKeyHandler(u *url.URL, h http.Header, createKeyRequest *CreateKeyRequest, c *Context) (int, http.Header, *CreateKeyResponse, error) {
	//var err error
	//defer CatchPanic(&err, "ListKeysRequest")

	log.Println("CreateKeyHandler: Starting...")

	// Authoritze the request
	if !AuthorizeRequest("POST", u, h) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Encrypt the key with the master key
	metadata, err := KmsCrypto.CreateKey(createKeyRequest.Description)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &CreateKeyResponse{KeyMetadata: metadata}, nil
}

// listKeysHandler
type ListKeysRequest struct {
}

// ListKeysResponse
type ListKeysResponse struct {
	KeyMetadata []KeyMetadata `json:"KeyMetadata"`
}

// listKeysHandler will list all the stored
func listKeysHandler(u *url.URL, h http.Header, listKeysRequest *ListKeysRequest, c *Context) (int, http.Header, *ListKeysResponse, error) {
	//var err error
	//defer CatchPanic(&err, "ListKeysRequest")

	log.Println("ListKeysRequest: Starting...")

	// Authoritze the request
	if !AuthorizeRequest("POST", u, h) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Encrypt the key with the master key
	metadata, err := KmsCrypto.ListKeys()
	if err != nil {
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &ListKeysResponse{KeyMetadata: metadata}, nil
}

// GenerateDataKeyRequest
type GenerateDataKeyRequest struct {
	KeyID string `json:"KeyID"`
}

// GenerateDataKeyResponse
type GenerateDataKeyResponse struct {
	Plaintext      []byte `json:"Plaintext"`
	CiphertextBlob []byte `json:"CiphertextBlob"`
}

// generateDataKeyHandler will generate a new AES key for use by a client
func generateDataKeyHandler(u *url.URL, h http.Header, dataKeyRequest *GenerateDataKeyRequest, c *Context) (int, http.Header, *GenerateDataKeyResponse, error) {
	//var err error
	//defer CatchPanic(&err, "GenerateDataKeyRequest")

	log.Println("GenerateDataKeyRequest: Starting...")

	// Authoritze the request
	if !AuthorizeRequest("POST", u, h) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Create a new key
	aesKey := GenerateAesSecret()

	// Encrypt the key with the master key
	encryptedData, err := KmsCrypto.Encrypt(aesKey, dataKeyRequest.KeyID)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &GenerateDataKeyResponse{Plaintext: aesKey, CiphertextBlob: encryptedData}, nil
}

// EncryptRequest
type EncryptRequest struct {
	KeyID     string `json:"KeyID"`
	Plaintext []byte `json:"Plaintext"`
}

// EncryptResponse
type EncryptResponse struct {
	CiphertextBlob []byte `json:"CiphertextBlob"`
}

// encryptHandler will encrypt the passed data with the specified key
func encryptHandler(u *url.URL, h http.Header, encryptRequest *EncryptRequest, c *Context) (int, http.Header, *EncryptResponse, error) {
	//var err error
	//defer CatchPanic(&err, "EncryptHandler")

	log.Println("EncryptHandler: Starting...")

	// Authoritze the request
	if !AuthorizeRequest("POST", u, h) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Encrypt the data with the key specified and return the encrypted data
	encryptedData, err := KmsCrypto.Encrypt(encryptRequest.Plaintext, encryptRequest.KeyID)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &EncryptResponse{CiphertextBlob: encryptedData}, nil
}

// DecryptRequest
type DecryptRequest struct {
	KeyID          string `json:"KeyID"`
	CiphertextBlob []byte `json:"CiphertextBlob"`
}

// DecryptResponse
type DecryptResponse struct {
	Plaintext []byte `json:"Plaintext"`
}

// decryptHandler will decrypt the passed data with the specified key
func decryptHandler(u *url.URL, h http.Header, decryptRequest *DecryptRequest, c *Context) (int, http.Header, *DecryptResponse, error) {
	//var err error
	//defer CatchPanic(&err, "decryptHandler")

	log.Println("DecryptHandler: Starting...")

	// Authoritze the request
	if !AuthorizeRequest("POST", u, h) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Decrypt
	decryptedData, err := KmsCrypto.Decrypt(decryptRequest.CiphertextBlob, decryptRequest.KeyID)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, nil
	}

	return http.StatusOK, nil, &DecryptResponse{Plaintext: decryptedData}, nil
}

// AuthorizeRequest - Will check the request authorization
func AuthorizeRequest(method string, u *url.URL, h http.Header) bool {

	date := h.Get("x-kms-date")
	resource := u.Path
	authRequestKey := fmt.Sprintf("%s\n%s\n%s", method, date, resource)

	authorization := h.Get("Authorization")

	hmac := GetHmac256(authRequestKey, SharedKey)

	if authorization != hmac {
		log.Printf("Authorization FAILED: Auth: %s HMAC: %s RequestKey: \n%s", authorization, hmac, authRequestKey)
	}

	// Was the passed value the same as we expected?
	return authorization == hmac
}

// Get the request address
func RequestAddr(r *http.Request) string {
	// Get the IP of the request
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
