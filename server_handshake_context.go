package dtls

import (
	"bytes"
	"errors"
	"log"
)

type serverHandshake struct {
	baseHandshakeContext
}

func (sh *serverHandshake) beginHandshake() {
	sh.currentFlight = 1
}

func (sh *serverHandshake) continueHandshake(message *Handshake) (complete bool, err error) {
	sh.receiveMessage(message)
	if sh.currentFlight == 1 && sh.isFlightOneComplete() {
		sh.sendFlightTwo()
		sh.currentFlight = 3
		return false, nil
	}
	if sh.currentFlight == 3 {
		if sh.clientKeyExchange != nil && sh.masterSecret == nil {
			err := sh.handleKeyExchange()
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
	clientHello, err := ReadHandshakeClientHello(sh.clientHello.Fragment)
	cipherSuite := findCommonCipherSuite(clientHello.CipherSuites, CipherSuites)
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
	sh.serverRandom = NewRandom()

	serverHello := HandshakeServerHello{
		ServerVersion:     DTLS_10,
		Random:            sh.serverRandom,
		CipherSuite:       cipherSuite,
		CompressionMethod: compressionMethod,
	}
	sh.serverHello = sh.buildNextHandshakeMessage(ServerHello, serverHello.Bytes())
	serverKeyExchange, err := sh.keyAgreement.GenerateServerKeyExchange()
	if err != nil {
		return err
	}
	sh.serverKeyExchange = sh.buildNextHandshakeMessage(ServerKeyExchange, serverKeyExchange)
	sh.serverHelloDone = sh.buildNextHandshakeMessage(ServerHelloDone, []byte{})
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

func findCommonCipherSuite(client, server []*CipherSuite) *CipherSuite {
	for _, suiteA := range client {
		for _, suiteB := range server {
			if suiteA.id == suiteB.id {
				return suiteA
			}
		}
	}
	return nil
}

func findCommonCompressionMethod(methods []CompressionMethod) (CompressionMethod, bool) {
	for _, method := range methods {
		if method == CompressionNone {
			return CompressionNone, true
		}
	}
	return 255, false
}

func (sh *serverHandshake) handleKeyExchange() error {
	clientKeyExchange, err := ReadClientKeyExchange(sh.clientKeyExchange.Fragment)
	if err != nil {
		log.Printf("Error while reading client key exchange: %v", err)
		return err
	}
	preMasterSecret, err := sh.keyAgreement.ProcessClientKeyExchange(clientKeyExchange)
	if err != nil {
		log.Printf("Error while processing client key exchange: %v", err)
		return err
	}
	masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
		keysFromPreMasterSecret(preMasterSecret, sh.clientRandom.Bytes(), sh.serverRandom.Bytes(),
			sh.cipherSuite.macLen, sh.cipherSuite.keyLen)
	sh.masterSecret = masterSecret
	sh.Conn.pendingWriteState.Cipher = sh.cipherSuite.cipher(clientKey)
	sh.Conn.pendingWriteState.Mac = sh.cipherSuite.mac(clientMAC)
	sh.Conn.pendingReadState.Cipher = sh.cipherSuite.cipher(serverKey)
	sh.Conn.pendingReadState.Mac = sh.cipherSuite.mac(serverMAC)
	return nil
}

func (sh *serverHandshake) isFlightThreeComplete() (complete bool, err error) {
	if sh.clientFinished == nil {
		return false, nil
	}
	clientFinished, err := ReadHandshakeFinished(sh.clientFinished.Fragment)
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
	serverFinished := &HandshakeFinished{VerifyData: sh.finishedHash.serverSum(sh.masterSecret)}
	sh.serverFinished = sh.buildNextHandshakeMessage(Finished, serverFinished.Bytes())
}

func (sh *serverHandshake) sendFlightFour() {
	sh.prepareFlightFour()
	sh.Conn.sendChangeCipherSpec()
	sh.sendHandshakeMessage(sh.serverFinished)
}
