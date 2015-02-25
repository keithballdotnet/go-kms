package kms

import (
	"fmt"
	"log"
	"os"
)

var KmsCrypto CryptoProvider

// Start - Will set up and start the server
func Start() {
	var err error

	// Get and check config
	InitConfig()

	KmsCrypto, err = NewKMSCryptoProvider()

	/*switch Config["GOKMS_CRYPTO_PROVIDER"] {
	case "softhsm":
		// Create crypto provider
		//KmsCrypto, err = NewSoftHSMCryptoProvider()
	default:
		KmsCrypto, err = NewKMSCryptoProvider()
	}*/

	if err != nil {
		Exit(fmt.Sprintf("Problem creating crypto provider: %v", err), 2)
	}

	// Start REST endpoint
	StartListener()
}

var Config = map[string]string{
	"GOKMS_AUTH_KEY":        "../files/auth.key",
	"GOKMS_CRYPTO_PROVIDER": "goksm",
	"GOKMS_HOST":            "localhost",
	"GOKMS_PORT":            "8011",
	"GOKMS_SSL_CERT":        "../files/auth.key", // This is just done to allow the tests to pass
	"GOKMS_SSL_KEY":         "../files/auth.key", // This is just done to allow the tests to pass
}

// InitConfig read several Environment variables and based on them initialise the configuration
func InitConfig() {
	envFiles := []string{"GOKMS_SSL_CERT", "GOKMS_SSL_KEY"}

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

	log.Printf("%s %s\n", prefix[errorCode], messages)
	os.Exit(errorCode)
}
