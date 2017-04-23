package dtls

import (
	"bytes"
	"errors"
	"fmt"
	"log"
)

type serverHandshake struct {
	baseHandshakeContext
}

func (sh *serverHandshake) beginHandshake() {
	sh.currentFlight = 1
}

func (sh *serverHandshake) continueHandshake(message *handshake) (complete bool, err error) {
	sh.receiveMessage(message)
	if sh.currentFlight == 1 && sh.isFlightOneComplete() {
		err := sh.sendFlightTwo()
		if err == nil {
			sh.currentFlight = 3
		} else {
			log.Printf("Error while sending flight two: %s", err)
		}
		return false, err
	}
	if sh.currentFlight == 3 {
		log.Printf("We're in flight 3, state is\n%+v", sh.baseHandshakeContext)
		if sh.clientKeyExchange != nil && sh.masterSecret == nil {
			log.Printf("Handling client key exchange")
			err := sh.handleKeyExchange()
			if err != nil {
				log.Printf("Error while handling client key exchange")
			}
			return false, err
		}
		complete, err := sh.isFlightThreeComplete()
		if complete && err == nil {
			sh.sendFlightFour()
		}
		return complete, err
	}
	return false, nil
}

func (sh *serverHandshake) isFlightOneComplete() bool {
	return sh.clientHello != nil
}

func (sh *serverHandshake) prepareFlightTwo() error {
	clientHello, err := readHandshakeClientHello(sh.clientHello.Fragment)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to read client hello: %s", err))
	}
	cipherSuite := findCommonCipherSuite(clientHello.CipherSuites, cipherSuites)
	if cipherSuite == nil {
		return errors.New("Client does not support any cipher suites we support")
	}
	sh.cipherSuite = *cipherSuite
	sh.keyAgreement = cipherSuite.KeyAgreement()
	compressionMethod, ok := findCommonCompressionMethod(clientHello.CompressionMethods)
	if !ok {
		return errors.New("Client does not support any compression methods we support")
	}
	sh.clientRandom = clientHello.Random
	sh.serverRandom = newRandom()

	srvHello := handshakeServerHello{
		ServerVersion:     DTLS_10,
		Random:            sh.serverRandom,
		CipherSuite:       cipherSuite,
		CompressionMethod: compressionMethod,
	}
	sh.serverHello = sh.buildNextHandshakeMessage(serverHello, srvHello.Bytes())
	srvKeyExchange, err := sh.keyAgreement.generateServerKeyExchange()
	if err != nil {
		return err
	}
	sh.serverKeyExchange = sh.buildNextHandshakeMessage(serverKeyExchange, srvKeyExchange)
	sh.serverHelloDone = sh.buildNextHandshakeMessage(serverHelloDone, []byte{})
	return nil
}

func (sh *serverHandshake) sendFlightTwo() error {
	if err := sh.prepareFlightTwo(); err != nil {
		return err
	}
	sh.sendHandshakeMessage(sh.serverHello)
	sh.sendHandshakeMessage(sh.serverKeyExchange)
	sh.sendHandshakeMessage(sh.serverHelloDone)
	return nil
}

func findCommonCipherSuite(client, server []*cipherSuite) *cipherSuite {
	log.Printf("Client supports ciphersuites: %+v", client)
	log.Printf("We support: %+v", server)
	for _, suiteA := range client {
		for _, suiteB := range server {
			if suiteA.id == suiteB.id {
				return suiteA
			}
		}
	}
	return nil
}

func findCommonCompressionMethod(methods []compressionMethod) (compressionMethod, bool) {
	for _, method := range methods {
		if method == compressionNone {
			return compressionNone, true
		}
	}
	return 255, false
}

func (sh *serverHandshake) handleKeyExchange() error {
	clientKeyExchange, err := readClientKeyExchange(sh.clientKeyExchange.Fragment)
	if err != nil {
		log.Printf("Error while reading client key exchange: %v", err)
		return err
	}
	preMasterSecret, err := sh.keyAgreement.processClientKeyExchange(clientKeyExchange)
	log.Printf("Premaster secret is %x", preMasterSecret)
	if err != nil {
		log.Printf("Error while processing client key exchange: %v", err)
		return err
	}
	masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
		keysFromPreMasterSecret(preMasterSecret, sh.clientRandom.Bytes(), sh.serverRandom.Bytes(),
			sh.cipherSuite.macLen, sh.cipherSuite.keyLen)
	sh.masterSecret = masterSecret
	sh.Conn.pendingWriteState.Cipher = sh.cipherSuite.cipher(serverKey)
	sh.Conn.pendingWriteState.Mac = sh.cipherSuite.mac(serverMAC)
	sh.Conn.pendingReadState.Cipher = sh.cipherSuite.cipher(clientKey)
	sh.Conn.pendingReadState.Mac = sh.cipherSuite.mac(clientMAC)
	logMasterSecret(sh.clientRandom.Bytes(), masterSecret)
	return nil
}

func (sh *serverHandshake) isFlightThreeComplete() (complete bool, err error) {
	if sh.clientFinished == nil {
		return false, nil
	}
	clientFinished, err := readHandshakeFinished(sh.clientFinished.Fragment)
	if err != nil {
		return true, err
	}
	sh.finishedHash = newFinishedHash()
	sh.finishedHash.Write(sh.clientHello.Bytes())
	sh.finishedHash.Write(sh.serverHello.Bytes())
	sh.finishedHash.Write(sh.serverKeyExchange.Bytes())
	sh.finishedHash.Write(sh.serverHelloDone.Bytes())
	sh.finishedHash.Write(sh.clientKeyExchange.Bytes())
	if !bytes.Equal(clientFinished.VerifyData, sh.finishedHash.clientSum(sh.masterSecret)) {
		err = errors.New("Server sent incorrect verify data")
	}
	return true, err
}

func (sh *serverHandshake) prepareFlightFour() {
	sh.finishedHash.Write(sh.clientFinished.Bytes())
	serverFinished := &handshakeFinished{VerifyData: sh.finishedHash.serverSum(sh.masterSecret)}
	sh.serverFinished = sh.buildNextHandshakeMessage(finished, serverFinished.Bytes())
}

func (sh *serverHandshake) sendFlightFour() {
	sh.prepareFlightFour()
	sh.Conn.sendChangeCipherSpec()
	sh.sendHandshakeMessage(sh.serverFinished)
}
