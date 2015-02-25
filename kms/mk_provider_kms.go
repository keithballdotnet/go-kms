package kms

import (
	"fmt"
	"os"
)

// GoKMSMasterKeyProvider is an implementation of aquiring a MASTER key using a derived key
type GoKMSMasterKeyProvider struct {
}

// NewHSMMasterKeyProvider
func NewGoKMSMasterKeyProvider() (GoKMSMasterKeyProvider, error) {
	// Ensure our config is ok...
	SetGOKSMMasterKeyProviderConfig()

	return GoKMSMasterKeyProvider{}, nil
}

// SetConfig will check any required settings for this crypto-provider
func SetGOKSMMasterKeyProviderConfig() {
	providerConfig := map[string]string{
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

	return
}

// GetKey will return the master key
func (mkp GoKMSMasterKeyProvider) GetKey() ([]byte, error) {

	// Derive key from pass phrase
	if len(Config["GOKMS_KSMC_PASSPHRASE"]) < 10 {
		Exit(fmt.Sprintf("The pass phrase must be at least 10 characters long is only %v characters", len(Config["GOKMS_KSMC_PASSPHRASE"])), 2)
	}

	// Derive master key from given pass phrase
	return DeriveAESKey(Config["GOKMS_KSMC_PASSPHRASE"], []byte{}), nil
}
