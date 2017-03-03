package dtls

import (
	"log"
)

type clientHandshake struct {
	baseHandshakeContext
}

func (ch *clientHandshake) beginHandshake() {
	ch.sendFlightOne()
	ch.currentFlight = 2
}

func (ch *clientHandshake) continueHandshake(message *Handshake) (complete bool, err error) {
	if ch.currentFlight == 2 && message.MsgType == HelloVerifyRequest {
		helloVerifyRequest, err := ReadHandshakeHelloVerifyRequest(message.Fragment)
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
	if ch.currentFlight == 4 && ch.isFlightFourComplete() {
		return true, nil
	}
	return false, nil
}

func (ch *clientHandshake) prepareFlightOne() {
	clientHello := HandshakeClientHello{
		ClientVersion: DTLS_10,
		Random:        ch.clientRandom,
		SessionID:     ch.sessionID,
		Cookie:        ch.cookie,
		CipherSuites:  CipherSuites,
		CompressionMethods: []CompressionMethod{
			CompressionNone,
		},
	}
	ch.clientHello = ch.buildNextHandshakeMessage(ClientHello, clientHello.Bytes())
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
func (ch *clientHandshake) prepareFlightThree() {
	serverHello, err := ReadHandshakeServerHello(ch.serverHello.Fragment)
	if err != nil {
		log.Printf("Error while reading server hello: %v", err)
		return
	}
	ch.serverRandom = serverHello.Random
	cipherSuite := serverHello.CipherSuite
	keyAgreement := cipherSuite.KeyAgreement()
	ch.Conn.pendingReadState.CompressionMethod = serverHello.CompressionMethod
	ch.Conn.pendingWriteState.CompressionMethod = serverHello.CompressionMethod
	ch.sessionID = serverHello.SessionID
	serverKeyExchange, err := ReadHandshakeServerKeyExchange(ch.serverKeyExchange.Fragment)
	if err != nil {
		log.Printf("Error while reading server key exchange: %v", err)
		return
	}
	if err = keyAgreement.ProcessServerKeyExchange(ch.clientRandom, ch.serverRandom, serverKeyExchange); err != nil {
		log.Printf("Error while processing server key exchange: %v", err)
		return
	}
	preMasterSecret, clientKeyExchange, err := keyAgreement.GenerateClientKeyExchange()
	if err != nil {
		log.Printf("Error while generating client key exchange: %v", err)
		return
	}
	ch.clientKeyExchange = ch.buildNextHandshakeMessage(ClientKeyExchange, clientKeyExchange.Bytes())
	masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
		keysFromPreMasterSecret(preMasterSecret, ch.clientRandom.Bytes(), ch.serverRandom.Bytes(),
			cipherSuite.macLen, cipherSuite.keyLen)
	ch.Conn.pendingWriteState.Cipher = cipherSuite.cipher(clientKey)
	ch.Conn.pendingWriteState.Mac = cipherSuite.mac(clientMAC)
	ch.Conn.pendingReadState.Cipher = cipherSuite.cipher(serverKey)
	ch.Conn.pendingReadState.Mac = cipherSuite.mac(serverMAC)
	logMasterSecret(ch.clientRandom.Bytes(), masterSecret)

	finishedHash := newFinishedHash()
	finishedHash.Write(ch.clientHello.Bytes())
	finishedHash.Write(ch.serverHello.Bytes())
	finishedHash.Write(ch.serverKeyExchange.Bytes())
	finishedHash.Write(ch.serverHelloDone.Bytes())
	finishedHash.Write(ch.clientKeyExchange.Bytes())
	finishedMessage := new(HandshakeFinished)
	finishedMessage.VerifyData = finishedHash.clientSum(masterSecret)
	ch.clientFinished = ch.buildNextHandshakeMessage(Finished, finishedMessage.Bytes())
}

func (ch *clientHandshake) sendFlightThree() {
	ch.prepareFlightThree()
	ch.sendHandshakeMessage(ch.clientKeyExchange)
	ch.Conn.sendChangeCipherSpec()
	ch.sendHandshakeMessage(ch.clientFinished)
}

func (ch *clientHandshake) isFlightFourComplete() bool {
	return ch.serverFinished != nil
}
