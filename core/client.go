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
	"syscall"
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
}

func (client *Client) copyOperation(h1 []byte) {
	conf, reader, writer := client.conf, client.reader, client.writer
	content, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()))
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	rbuf := make([]byte, 32)
	if _, err = io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Fatal("The server may be running an incompatible version")
		} else {
			log.Fatal(err)
		}
	}
	h3 := rbuf
	wh3 := auth3store(conf, client.version, h2)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	if IsTerminal(int(syscall.Stderr)) {
		os.Stderr.WriteString("Sent\n")
	}
}

func (client *Client) pasteOperation(h1 []byte, isMove bool) {
	conf, reader, writer := client.conf, client.reader, client.writer
	opcode := byte('G')
	if isMove {
		opcode = byte('M')
	}
	h2 := auth2get(conf, client.version, h1, opcode)
	writer.WriteByte(opcode)
	writer.Write(h2)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 120)
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if err == io.ErrUnexpectedEOF {
			if nbread < 80 {
				log.Fatal("The clipboard might be empty")
			} else {
				log.Fatal("The server may be running an incompatible version")
			}
		} else {
			log.Fatal(err)
		}
	}
	h3 := rbuf[0:32]
	ciphertextWithNonceLen := binary.LittleEndian.Uint64(rbuf[32:40])
	encryptSkID := rbuf[40:48]
	ts := rbuf[48:56]
	signature := rbuf[56:120]
	wh3 := auth3get(conf, client.version, h2, encryptSkID, ts, signature)
	if subtle.ConstantTimeCompare(wh3, h3) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	elapsed := time.Since(time.Unix(int64(binary.LittleEndian.Uint64(ts)), 0))
	if elapsed >= conf.TTL {
		log.Fatal("Clipboard content is too old")
	}
	if bytes.Equal(conf.EncryptSkID, encryptSkID) == false {
		wEncryptSkIDStr := binary.LittleEndian.Uint64(conf.EncryptSkID)
		encryptSkIDStr := binary.LittleEndian.Uint64(encryptSkID)
		log.Fatal(fmt.Sprintf("Configured key ID is %v but content was encrypted using key ID %v",
			wEncryptSkIDStr, encryptSkIDStr))
	}
	ciphertextWithNonce := make([]byte, ciphertextWithNonceLen)

	client.conn.SetDeadline(time.Now().Add(conf.DataTimeout))
	if _, err := io.ReadFull(reader, ciphertextWithNonce); err != nil {
		if err == io.ErrUnexpectedEOF {
			log.Fatal("The server may be running an incompatible version")
		} else {
			log.Fatal(err)
		}
	}
	if ed25519.Verify(conf.SignPk, ciphertextWithNonce, signature) != true {
		log.Fatal("Signature doesn't verify")
	}
	nonce := ciphertextWithNonce[0:24]
	cipher, err := chacha20.NewCipher(conf.EncryptSk, nonce)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext := ciphertextWithNonce[24:]
	cipher.XORKeyStream(ciphertext, ciphertext)
	content := ciphertext
	binary.Write(os.Stdout, binary.LittleEndian, content)
}

// RunClient - Process a client query
func RunClient() {
	// Copy-pasted configuration code from piknik.go
	log.SetFlags(0)

	isCopy := flag.Bool("copy", false, "store content (copy)")
	_ = flag.Bool("paste", false, "retrieve the content (paste) - this is the default action")
	isMove := flag.Bool("move", false, "retrieve and delete the clipboard content")
	isGenKeys := flag.Bool("genkeys", false, "generate keys")
	isDeterministic := flag.Bool("password", false, "derive the keys from a password (default=random keys)")
	maxClients := flag.Uint64("maxclients", 10, "maximum number of simultaneous client connections")
	maxLenMb := flag.Uint64("maxlen", 0, "maximum content length to accept in Mb (0=unlimited)")
	timeout := flag.Uint("timeout", 10, "connection timeout (seconds)")
	dataTimeout := flag.Uint("datatimeout", 3600, "data transmission timeout (seconds)")
	isVersion := flag.Bool("version", false, "display package version")

	defaultConfigFile := "~/.piknik.toml"
	if runtime.GOOS == "windows" {
		defaultConfigFile = "~/piknik.toml"
	}
	configFile := flag.String("config", defaultConfigFile, "configuration file")
	flag.Parse()
	if *isVersion {
		version()
		return
	}
	tomlData, err := ioutil.ReadFile(expandConfigFile(*configFile))
	if err != nil && *isGenKeys == false {
		log.Fatal(err)
	}
	var tomlConf tomlConfig
	if _, err = toml.Decode(string(tomlData), &tomlConf); err != nil {
		log.Fatal(err)
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
	if *isGenKeys {
		leKey := ""
		if *isDeterministic {
			leKey = getPassword("Password> ")
		}
		genKeys(conf, *configFile, leKey)
		return
	}
	pskHex := tomlConf.Psk
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		log.Fatal(err)
	}
	conf.Psk = psk
	if encryptSkHex := tomlConf.EncryptSk; encryptSkHex != "" {
		encryptSk, err := hex.DecodeString(encryptSkHex)
		if err != nil {
			log.Fatal(err)
		}
		conf.EncryptSk = encryptSk
	}
	if signPkHex := tomlConf.SignPk; signPkHex != "" {
		signPk, err := hex.DecodeString(signPkHex)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(err)
		}
		switch len(signSk) {
		case 32:
			if len(conf.SignPk) != 32 {
				log.Fatal("Public signing key required")
			}
			signSk = append(signSk, conf.SignPk...)
		case 64:
		default:
			log.Fatal("Unsupported length for the secret signing key")
		}
		conf.SignSk = signSk
	}
	conf.MaxClients = *maxClients
	conf.MaxLen = *maxLenMb * 1024 * 1024
	conf.Timeout = time.Duration(*timeout) * time.Second
	conf.DataTimeout = time.Duration(*dataTimeout) * time.Second
	conf.TrustedIPCount = uint64(float64(conf.MaxClients) * 0.1)
	if conf.TrustedIPCount < 1 {
		conf.TrustedIPCount = 1
	}
	// End copy-pasted data

	conn, err := net.DialTimeout("tcp", conf.Connect, conf.Timeout)
	if err != nil {
		log.Fatal(fmt.Sprintf("Unable to connect to %v - Is a Piknik server running on that host?",
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
		log.Fatal(err)
	}
	h0 := auth0(conf, client.version, r)
	writer.Write([]byte{client.version})
	writer.Write(r)
	writer.Write(h0)
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	rbuf := make([]byte, 65)
	if nbread, err := io.ReadFull(reader, rbuf); err != nil {
		if nbread < 2 {
			log.Fatal("The server rejected the connection - Check that it is running the same Piknik version or retry later")
		} else {
			log.Fatal("The server doesn't support this protocol")
		}
	}
	if serverVersion := rbuf[0]; serverVersion != client.version {
		log.Fatal(fmt.Sprintf("Incompatible server version (client version: %v - server version: %v)",
			client.version, serverVersion))
	}
	r2 := rbuf[1:33]
	h1 := rbuf[33:65]
	wh1 := auth1(conf, client.version, h0, r2)
	if subtle.ConstantTimeCompare(wh1, h1) != 1 {
		log.Fatal("Incorrect authentication code")
	}
	if *isCopy {
		client.copyOperation(h1)
	} else {
		client.pasteOperation(h1, *isMove)
	}
}
