package dtls

import (
	"fmt"
)

func (hc *handshakeContext) isFlightTwoComplete() bool {
	if hc.serverHello == nil {
		return false
	}
	if hc.serverHello.CipherSuite.KeyAgreement != dheKA && hc.serverCertificate == nil {
		return false
	}
	if hc.serverHello.CipherSuite.KeyAgreement == dheKA && hc.serverKeyExchange == nil {
		return false
	}
	if hc.serverHelloDone == nil {
		return false
	}
	return true
}

func (hc *handshakeContext) isFlightFourComplete() bool {
	if hc.serverFinished == nil {
		return false
	}
	return true
}

func (hc *handshakeContext) doFlightOne() {
	clientHello := HandshakeClientHello{
		ClientVersion: DTLS_10,
		Random:        hc.clientRandom,
		SessionID:     hc.sessionID,
		Cookie:        hc.cookie,
		CipherSuites:  CipherSuites,
		CompressionMethods: []CompressionMethod{
			CompressionNone,
		},
	}
	hc.clientHello = c.makeHandshake(ClientHello, clientHello.Bytes())
	hc.sendFlightOne()
}

func (hc *handshakeContext) sendFlightOne() {
	hc.sendRecord(TypeHandshake, hc.clientHello.Bytes())
}

func (hc *handshakeContext) doFlightThree() {

	serverHello, err := ReadHandshakeServerHello(handshakeBuffer)
	if err != nil {
		panic(fmt.Sprintf("Error while reading server hello: %v", err))
	}
	hc.serverRandom = serverHello.Random
	hc.CipherSuite = serverHello.CipherSuite
	hc.KeyAgreement = hc.CipherSuite.KeyAgreement()
	hc.pendingReadState.CompressionMethod = serverHello.CompressionMethod
	hc.pendingWriteState.CompressionMethod = serverHello.CompressionMethod
	hc.sessionID = serverHello.SessionID

	serverKeyExchange, err := ReadHandshakeServerKeyExchange(handshakeBuffer)
	if err != nil {
		panic(fmt.Sprintf("Error while reading server key exchange: %v", err))
	}
	if err = hc.KeyAgreement.ProcessServerKeyExchange(hc.clientRandom, hc.serverRandom, serverKeyExchange); err != nil {
		panic(fmt.Sprintf("Error while processing server key exchange: %v", err))
	}

	preMasterSecret, clientKeyExchange, err := hc.KeyAgreement.GenerateClientKeyExchange()
	if err != nil {
		panic(fmt.Sprintf("Error while generating client key exchange: %v", err))
	}
	hc.clientKeyExchange = hc.makeHandshake(ClientKeyExchange, clientKeyExchange.Bytes())

	masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
		keysFromPreMasterSecret(preMasterSecret, hc.clientRandom.Bytes(), hc.serverRandom.Bytes(), hc.CipherSuite.macLen, hc.CipherSuite.keyLen)

	logMasterSecret(hc.clientRandom.Bytes(), masterSecret)

	hc.pendingWriteState.Cipher = hc.CipherSuite.cipher(clientKey)
	hc.pendingWriteState.Mac = hc.CipherSuite.mac(clientMAC)
	hc.pendingReadState.Cipher = hc.CipherSuite.cipher(serverKey)
	hc.pendingReadState.Mac = hc.CipherSuite.mac(serverMAC)

	finishedMessage := new(HandshakeFinished)
	finishedMessage.VerifyData = hc.clientFinishedSum()
	hc.clientFinished, err = hc.makeHandshake(Finished, finishedMessage.Bytes())
}
