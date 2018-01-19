package common

import (
	"sync"
	"time"
)

const (
	// Version - Piknik version
	Version = "0.9.1"
	// DomainStr - BLAKE2 domain (personalization)
	DomainStr = "PK"
	// DefaultListen - Default value for the Listen parameter
	DefaultListen = "0.0.0.0:8075"
	// DefaultConnect - Default value for the Connect parameter
	DefaultConnect = "127.0.0.1:8075"
	// DefaultTTL - Time after the clipboard is considered obsolete, in seconds
	DefaultTTL = 7 * 24 * time.Hour
)

type tomlConfig struct {
	Connect     string
	Listen      string
	EncryptSk   string
	EncryptSkID uint64
	Psk         string
	SignPk      string
	SignSk      string
	Timeout     uint
	DataTimeout uint
	TTL         uint
}

// Conf - Shared config
type Conf struct {
	Connect        string
	Listen         string
	MaxClients     uint64
	MaxLen         uint64
	EncryptSk      []byte
	EncryptSkID    []byte
	Psk            []byte
	SignPk         []byte
	SignSk         []byte
	Timeout        time.Duration
	DataTimeout    time.Duration
	TTL            time.Duration
	TrustedIPCount uint64
}

// StoredContent - Paste buffer
type StoredContent struct {
	sync.RWMutex

	encryptSkID         []byte
	ts                  []byte
	signature           []byte
	ciphertextWithNonce []byte
}
