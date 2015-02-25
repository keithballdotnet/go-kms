package kms

import (
	"time"
)

// KeyMetadata is the associated meta data of any key
type KeyMetadata struct {
	KeyID        string    `json:"KeyId"`
	CreationDate time.Time `json:"CreationDate"`
	Description  string    `json:"Description"`
	Enabled      bool      `json:"Enabled"`
}

// Key is a represention of a key
type Key struct {
	KeyMetadata KeyMetadata `json:"KeyMetadata"`
	AESKey      []byte      `json:"AESKey"`
}

// CryptoProvider provides an interface for crypto provider solutions
type CryptoProvider interface {
	CreateKey(description string) (KeyMetadata, error)
	ListKeys() ([]KeyMetadata, error)
	GetKey(KeyID string) (Key, error)
	EnableKey(KeyID string) (KeyMetadata, error)
	DisableKey(KeyID string) (KeyMetadata, error)
	Encrypt(data []byte, KeyID string) ([]byte, error)
	Decrypt(data []byte) ([]byte, string, error)
	ReEncrypt(data []byte, KeyID string) ([]byte, string, error)
	GenerateAesKey() []byte
}

// MasterKeyProvider provides a mechanism to load a master key
type MasterKeyProvider interface {
	GetKey() ([]byte, error)
}
