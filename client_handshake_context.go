package dtls

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"log"
)

type clientHandshake struct {
	baseHandshakeContext
	extensions []*extension
}

func (ch *clientHandshake) beginHandshake() {
	ch.sendFlightOne()
	ch.currentFlight = 2
}

func (ch *clientHandshake) continueHandshake(message *handshake) (complete bool, err error) {
	if ch.currentFlight == 2 && message.MsgType == helloVerifyRequest {
		helloVerifyRequest, err := readHandshakeHelloVerifyRequest(message.Fragment)
		if err != nil {
			panic(err)
		}
		ch.cookie = helloVerifyRequest.Cookie
		ch.sendFlightOne()
		ch.nextReceiveSequenceNumber += 1
	} else {
		ch.receiveMessage(message)
	}
	if ch.currentFlight == 2 && ch.isFlightTwoComplete() {
		ch.sendFlightThree()
		ch.currentFlight = 4
		return false, nil
	}
	if ch.currentFlight == 4 {
		return ch.isFlightFourComplete()
	}
	return false, nil
}

func (ch *clientHandshake) prepareFlightOne() {
	cltHello := handshakeClientHello{
		ClientVersion: ch.Conn.version,
		Random:        ch.clientRandom,
		SessionID:     ch.sessionID,
		Cookie:        ch.cookie,
		CipherSuites:  cipherSuites,
		CompressionMethods: []compressionMethod{
			compressionNone,
		},
		Extensions: ch.extensions,
	}
	ch.clientHello = ch.buildNextHandshakeMessage(clientHello, cltHello.Bytes())
}

func (ch *clientHandshake) sendFlightOne() {
	ch.prepareFlightOne()
	ch.sendHandshakeMessage(ch.clientHello)
}

func (ch *clientHandshake) isFlightTwoComplete() bool {
	return ch.serverHello != nil &&
		ch.serverKeyExchange != nil &&
		ch.serverHelloDone != nil
}

func (ch *clientHandshake) verifyKeyExchange(serverHello handshakeServerHello, certificate []byte, serverKeyExchange handshakeServerKeyExchange) error {
	signedContent := append(append(ch.clientRandom.Bytes(), ch.serverRandom.Bytes()...), serverKeyExchange.Params.Bytes()...)
	if serverHello.HasExtension(serverExtensionCertificateTypeOpenPGP) {
		return ch.verifyOpenPGPKeyExchange(signedContent, certificate)
	}
	// TODO error out on not implemented
	return nil
}

func (ch *clientHandshake) verifyOpenPGPKeyExchange(signedContent, certificate []byte) error {
	openPgpCertificate, err := readOpenpgpCertificate(bytes.NewBuffer(certificate))
	if err != nil {
		log.Printf("Error while parsing openpgp certificate")
		return err
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(bytes.NewBuffer(openPgpCertificate.subkeyCert.cert)))
	if err != nil {
		log.Printf("Error while reading openpgp entity: %s", err)
		return err
	}
	log.Printf("Entity: %+v", entity)
	return nil

}

func (ch *clientHandshake) prepareFlightThree() {
	serverHello, err := readHandshakeServerHello(ch.serverHello.Fragment)
	if err != nil {
		log.Printf("Error while reading server hello: %v", err)
		return
	}
	ch.serverRandom = serverHello.Random
	cipherSuite := serverHello.CipherSuite
	ch.keyAgreement = cipherSuite.KeyAgreement()
	ch.Conn.pendingReadState.compressionMethod = serverHello.CompressionMethod
	ch.Conn.pendingWriteState.compressionMethod = serverHello.CompressionMethod
	ch.sessionID = serverHello.SessionID
	serverKeyExchange, err := readHandshakeServerKeyExchange(ch.serverKeyExchange.Fragment)
	if err != nil {
		log.Printf("Error while reading server key exchange: %v", err)
		return
	}
	if cipherSuite.signedKeyExchange {
		if ch.serverCertificate == nil {
			log.Printf("Server key exchange should be authenticated but no certificate was presented")
			return
		}
		if err := ch.verifyKeyExchange(serverHello, ch.serverCertificate.Fragment, serverKeyExchange); err != nil {
			log.Printf("Failed to verify server key exchange: %s", err)
			return
		}
	}
	if err = ch.keyAgreement.processServerKeyExchange(ch.clientRandom, ch.serverRandom, serverKeyExchange); err != nil {
		log.Printf("Error while processing server key exchange: %v", err)
		return
	}
	preMasterSecret, cltKeyExchange, err := ch.keyAgreement.generateClientKeyExchange()
	if err != nil {
		log.Printf("Error while generating client key exchange: %v", err)
		return
	}
	ch.clientKeyExchange = ch.buildNextHandshakeMessage(clientKeyExchange, cltKeyExchange.Bytes())
	masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
		keysFromPreMasterSecret(ch.Conn.version, preMasterSecret, ch.clientRandom.Bytes(), ch.serverRandom.Bytes(),
			cipherSuite.macLen, cipherSuite.keyLen)
	ch.masterSecret = masterSecret
	ch.Conn.pendingWriteState.Cipher = cipherSuite.cipher(clientKey)
	ch.Conn.pendingWriteState.Mac = cipherSuite.mac(clientMAC)
	ch.Conn.pendingReadState.Cipher = cipherSuite.cipher(serverKey)
	ch.Conn.pendingReadState.Mac = cipherSuite.mac(serverMAC)
	logMasterSecret(ch.clientRandom.Bytes(), masterSecret)

	ch.finishedHash = newFinishedHash()
	ch.finishedHash.Write(ch.clientHello.Bytes())
	ch.finishedHash.Write(ch.serverHello.Bytes())
	ch.finishedHash.Write(ch.serverKeyExchange.Bytes())
	ch.finishedHash.Write(ch.serverHelloDone.Bytes())
	ch.finishedHash.Write(ch.clientKeyExchange.Bytes())
	finishedMessage := new(handshakeFinished)
	if ch.Conn.version == DTLS_10 {
		finishedMessage.VerifyData = ch.finishedHash.clientSum10(masterSecret)
	} else if ch.Conn.version == DTLS_12 {
		finishedMessage.VerifyData = ch.finishedHash.clientSum12(masterSecret)
	}
	ch.clientFinished = ch.buildNextHandshakeMessage(finished, finishedMessage.Bytes())
}

func (ch *clientHandshake) sendFlightThree() {
	ch.prepareFlightThree()
	ch.sendHandshakeMessage(ch.clientKeyExchange)
	ch.Conn.sendChangeCipherSpec()
	ch.sendHandshakeMessage(ch.clientFinished)
}

func (ch *clientHandshake) isFlightFourComplete() (bool, error) {
	if ch.serverFinished == nil {
		return false, nil
	}
	serverFinished, err := readHandshakeFinished(ch.serverFinished.Fragment)
	if err != nil {
		return true, err
	}
	ch.finishedHash.Write(ch.clientFinished.Bytes())
	if ch.Conn.version == DTLS_10 && !bytes.Equal(serverFinished.VerifyData, ch.finishedHash.serverSum10(ch.masterSecret)) {
		err = errors.New("Server sent incorrect verify data")
	} else if ch.Conn.version == DTLS_12 && !bytes.Equal(serverFinished.VerifyData, ch.finishedHash.serverSum12(ch.masterSecret)) {
		err = errors.New("Server sent incorrect verify data")
	} else if ch.Conn.version != DTLS_10 && ch.Conn.version != DTLS_12 {
		// TODO: This should never happen
		err = errors.New("Unsupported version ...")
	}
	return true, err
}
