package kms

import (
	"fmt"
	"github.com/rcrowley/go-tigertonic"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	// This key is used for authentication with the server
	SharedKey = ""
)

// Start a HTTP listener
func StartListener() {

	// Set up the auth key
	SetupAuthenticationKey()

	// Set-up API listeners
	mux := tigertonic.NewTrieServeMux()
	mux.Handle("GET", "/api/v1/go-kms", tigertonic.Timed(tigertonic.Marshaled(GetHello), "GetHelloHandler", nil))

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

func GetHello(u *url.URL, h http.Header, _ interface{}) (int, http.Header, string, error) {
	log.Println("Got GET hello request")

	// Really simple hello
	return http.StatusOK, nil, "Server: GO-KMS", nil
}

// AuthorizeRequest - Will check the request authorization
func AuthorizeRequest(method string, u *url.URL, h http.Header) bool {

	date := h.Get("x-blocker-date")
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
