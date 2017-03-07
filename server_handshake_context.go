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
	if sh.currentFlight == 3 && sh.isFlightThreeComplete() {
		sh.sendFlightFour()
		return true, nil
	}
	return false, nil
}

func (sh *serverHandshake) isFlightOneComplete() bool {
	return sh.clientHello != nil
}

func (sh *serverHandshake) prepareFlightTwo() error {
	clientHello, err := ReadHandshakeClientHello(sh.clientHello.Fragment)
	cipherSuite, ok := findCommonCipherSuite(clientHello.CipherSuites, CipherSuites)
	if !ok {
		return errors.New("Client does not support any cipher suites we support")
	}
	compressionMethod, ok := findCommonCompressionMethod(clientHello.CompressionMethods)
	if !ok {
		return errors.New("Client does not support any compression methods we support")
	}
	sh.clientRandom = clientHello.Random
	sh.serverRandom = NewRandom()

	serverHello = HandshakeServerHello{
		ServerVersion:     DTLS_10,
		Random:            sh.serverRandom,
		CipherSuite:       cipherSuite,
		CompressionMethod: compressionMethod,
	}
	sh.serverHello = sh.buildNextHandshakeMessage(ServerHello, serverHello.Bytes())

}

func (sh *serverHandshake) sendFlightTwo() error {

}

func findCommonCipherSuite(client, server []*ChipherSuite) (*CipherSuite, bool) {
	for _, suiteA := range client {
		for _, suiteB := range server {
			if suiteA.id == suiteB.id {
				return suiteA, true
			}
		}
	}
	return nil, false
}

func findCommonCompressionMethod(methods []CompressionMethod) (CompressionMethod, bool) {
	for _, method := range methods {
		if method == CompressionNone {
			return CompressionNone, true
		}
	}
	return 255, false
}
