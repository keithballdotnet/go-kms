package kms

// CryptoProvider provides an interface for crypto provider solutions
type CryptoProvider interface {
	Encrypt(data []byte, KeyID string) ([]byte, error)
	Decrypt(data []byte, KeyID string) ([]byte, error)
}
