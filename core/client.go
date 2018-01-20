package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"flag"
	"encoding/hex"
	"io"
	"io/ioutil"
	"runtime"
	"log"
	"net"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/yawning/chacha20"
	"golang.org/x/crypto/ed25519"
	blake2b "github.com/minio/blake2b-simd"
)

// DefaultClientVersion - Default client version
const DefaultClientVersion = byte(5)

// Client - Client data
type Client struct {
	conf    Conf
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	version byte
	h1 []byte
}

func (client *Client) copyOperation(h1 []byte, input string) {
	conf, reader, writer := client.conf, client.reader, client.writer
	content := []byte(input)
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		log.Print(err)
	}
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()))
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Print(err)
	}
	opcode := byte('S')
	ciphertextWithNonce := make([]byte, 24+len(content))
	copy(ciphertextWithNonce, nonce)
	ciphertext := ciphertextWithNonce[24:]
	cipher.XORKeyStream(ciphertext, content)
	signature := ed25519.Sign(conf.SignSk, ciphertextWithNonce)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	h2 := auth2store(conf, client.version, h1, opcode, conf.EncryptSkID, ts, signature)
	writer.WriteByte(opcode)
	writer.Write(h2)
	ciphertextWithNonceLen := uint64(len(ciphertextWithNonce))
	binary.Write(writer, binary.LittleEndian, ciphertextWithNonceLen)
	writer.Write(conf.EncryptSkID)
	writer.Write(ts)
	writer.Write(signature)
	writer.Write(ciphertextWithNonce)
	if writer.Flush() != nil {
		log.Print(err)
	}
	rbuf := make([]byte, 32)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Print("The server may be running an incompatible version")
		} else {
			log.Print("something you can search for" + err.Error())
		}
	}
	h3 := rbuf
	wh3 := auth3store(conf, client.version, h2)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Print("Incorrect authentication code")
	}
	os.Stderr.WriteString("Sent\n")
}

func (client *Client) pasteOperation(h1 []byte, isMove bool) string {
	conf, reader, writer := client.conf, client.reader, client.writer
	opcode := byte('G')
	if isMove {
		opcode = byte('M')
	}
	h2 := auth2get(conf, client.version, h1, opcode)
	writer.WriteByte(opcode)
	writer.Write(h2)
	if err := writer.Flush(); err != nil {
		log.Print(err)
	}
	rbuf := make([]byte, 120)
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			if nbread < 80 {
				log.Print("The clipboard might be empty")
			} else {
				log.Print("The server may be running an incompatible version")
			}
		} else {
			log.Print(err)
		}
	}
	h3 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	encryptSkID := rbuf[40:48]
	ts := rbuf[48:56]
	signature := rbuf[56:120]
	wh3 := auth3get(conf, client.version, h2, encryptSkID, ts, signature)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Print("Incorrect authentication code")
	}
	elapsed := time.Since(time.Unix(int64(binary.LittleEndian.Uint64(ts)), 0))
	if elapsed >= conf.TTL {
		log.Print("Clipboard content is too old")
	}
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Print(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Print("The server may be running an incompatible version")
		} else {
			log.Print(err)
		}
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		log.Print("Signature doesn't verify")
	}
	nonce := ciphertextWithNonce[0:24]
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Print(err)
	}
	ciphertext := ciphertextWithNonce[24:]
	cipher.XORKeyStream(ciphertext, ciphertext)
	content := ciphertext
	binary.Write(os.Stdout, binary.LittleEndian, content)

	return string(content)
}

func Initialize() {
	// Copy-pasted configuration code from piknik.go
	log.SetFlags(0)

	flag.Bool("genkeys", false, "generate keys")
	flag.Bool("password", false, "derive the keys from a password (default=random keys)")
	flag.Uint64("maxclients", 10, "maximum number of simultaneous client connections")
	flag.Uint64("maxlen", 0, "maximum content length to accept in Mb (0=unlimited)")
	flag.Uint("timeout", 10, "connection timeout (seconds)")
	flag.Uint("datatimeout", 3600, "data transmission timeout (seconds)")
	flag.Bool("version", false, "display package version")

	defaultConfigFile := "~/.piknik.toml"
	if runtime.GOOS == "windows" {
		defaultConfigFile = "~/piknik.toml"
	}
	flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()
}

func get_client() Client {
	maxClients := uint64(10)
	maxLenMb := uint64(0)
	timeout := 10
	dataTimeout := 3600
	configFile := "~/Documents/.piknik.toml"

	tomlData, err := ioutil.ReadFile(expandConfigFile(configFile))
	if err != nil {
		log.Print(err)
	}
	var tomlConf tomlConfig
	if _, err = toml.Decode(string(tomlData), &tomlConf); err != nil {
		log.Print(err)
	}
	var conf Conf
	if tomlConf.Listen == "" {
		conf.Listen = DefaultListen
	} else {
		conf.Listen = tomlConf.Listen
	}
	if tomlConf.Connect == "" {
		conf.Connect = DefaultConnect
	} else {
		conf.Connect = tomlConf.Connect
	}	
	pskHex := tomlConf.Psk
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		log.Print(err)
	}
	conf.Psk = psk
	if encryptSkHex := tomlConf.EncryptSk; encryptSkHex != "" {
		encryptSk, err := hex.DecodeString(encryptSkHex)
		if err != nil {
			log.Print(err)
		}
		conf.EncryptSk = encryptSk
	}
	if signPkHex := tomlConf.SignPk; signPkHex != "" {
		signPk, err := hex.DecodeString(signPkHex)
		if err != nil {
			log.Print(err)
		}
		conf.SignPk = signPk
	}
	if encryptSkID := tomlConf.EncryptSkID; encryptSkID > 0 {
		conf.EncryptSkID = make([]byte, 8)
		binary.LittleEndian.PutUint64(conf.EncryptSkID, encryptSkID)
	} else if len(conf.EncryptSk) > 0 {
		hf, _ := blake2b.New(&blake2b.Config{
			Person: []byte(DomainStr),
			Size:   8,
		})
		hf.Write(conf.EncryptSk)
		encryptSkID := hf.Sum(nil)
		encryptSkID[7] &= 0x7f
		conf.EncryptSkID = encryptSkID
	}
	conf.TTL = DefaultTTL
	if ttl := tomlConf.TTL; ttl > 0 {
		conf.TTL = time.Duration(ttl) * time.Second
	}
	if signSkHex := tomlConf.SignSk; signSkHex != "" {
		signSk, err := hex.DecodeString(signSkHex)
		if err != nil {
			log.Print(err)
		}
		switch len(signSk) {
		case 32:
			if len(conf.SignPk) != 32 {
				log.Print("Public signing key required")
			}
			signSk = append(signSk, conf.SignPk...)
		case 64:
		default:
			log.Print("Unsupported length for the secret signing key")
		}
		conf.SignSk = signSk
	}
	conf.MaxClients = maxClients
	conf.MaxLen = maxLenMb * 1024 * 1024
	conf.Timeout = time.Duration(timeout) * time.Second
	conf.DataTimeout = time.Duration(dataTimeout) * time.Second
	conf.TrustedIPCount = uint64(float64(conf.MaxClients) * 0.1)
	if conf.TrustedIPCount < 1 {
		conf.TrustedIPCount = 1
	}
	// End copy-pasted data

	conn, err := net.DialTimeout("tcp", conf.Connect, conf.Timeout)
	if err != nil {
		log.Print(fmt.Sprintf("Unable to connect to %v - Is a Piknik server running on that host?",
			conf.Connect))
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(conf.Timeout))
	reader, writer := bufio.NewReader(conn), bufio.NewWriter(conn)
	client := Client{
		conf:    conf,
		conn:    conn,
		reader:  reader,
		writer:  writer,
		version: DefaultClientVersion,
	}
	r := make([]byte, 32)
	if _, err = rand.Read(r); err != nil {
		log.Print(err)
	}
	h0 := auth0(conf, client.version, r)
	writer.Write([]byte{client.version})
	writer.Write(r)
	writer.Write(h0)
	if err := writer.Flush(); err != nil {
		log.Print(err)
	}
	rbuf := make([]byte, 65)
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if nbread < 2 {
			log.Print("The server rejected the connection - Check that it is running the same Piknik version or retry later")
		} else {
			log.Print("The server doesn't support this protocol")
		}
	}
	if serverVersion := rbuf[0]; serverVersion != client.version {
		log.Print(fmt.Sprintf("Incompatible server version (client version: %v - server version: %v)",
			client.version, serverVersion))
	}
	r2 := rbuf[1:33]
	h1 := rbuf[33:65]
	wh1 := auth1(conf, client.version, h0, r2)
	if subtle.ConstantTimeCompare(wh1, h1) != 1 {
		log.Print("Incorrect authentication code")
	}
	client.h1 = h1
	return client
}

// RunClient - Process a client query
func Copy(input string) {
	client := get_client()
	client.copyOperation(client.h1, input)
}

func Paste() string {
	client := get_client()
	return client.pasteOperation(client.h1, false)
}
