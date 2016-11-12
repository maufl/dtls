package dtls

import (
	"bytes"
	"log"
)

func (c *Conn) handleHandshakeRecord(handshake Handshake) {
	c.finishedHash.Write(handshake.VerifyBytes())
	log.Printf("Writing %s to finished hash", handshake.MsgType)
	handshakeBuffer := bytes.NewBuffer(handshake.Fragment)
	switch handshake.MsgType {
	case HelloVerifyRequest:
		helloVerifyRequest, err := ReadHandshakeHelloVerifyRequest(handshakeBuffer)
		if err != nil {
			log.Printf("Error while reading hello verify request: %v", err)
			return
		}
		c.cookie = helloVerifyRequest.Cookie
		c.sendClientHello()
	case ServerHello:
		serverHello, err := ReadHandshakeServerHello(handshakeBuffer)
		if err != nil {
			log.Printf("Error while reading server hello: %v", err)
			return
		}
		c.pendingReadState.ServerRandom = serverHello.Random
		c.pendingWriteState.ServerRandom = serverHello.Random
		c.pendingReadState.CipherSuite = serverHello.CipherSuite
		c.pendingWriteState.CipherSuite = serverHello.CipherSuite
		c.pendingReadState.KeyAgreement = serverHello.CipherSuite.KeyAgreement()
		c.pendingWriteState.KeyAgreement = serverHello.CipherSuite.KeyAgreement()
		c.pendingReadState.CompressionMethod = serverHello.CompressionMethod
		c.pendingWriteState.CompressionMethod = serverHello.CompressionMethod
		c.sessionID = serverHello.SessionID
	case ServerKeyExchange:
		serverKeyExchange, err := ReadHandshakeServerKeyExchange(handshakeBuffer)
		if err != nil {
			log.Printf("Error while reading server key exchange: %v", err)
			return
		}
		if err = c.pendingReadState.KeyAgreement.ProcessServerKeyExchange(c.pendingReadState.ClientRandom, c.pendingReadState.ServerRandom, serverKeyExchange); err != nil {
			log.Printf("Error while processing server key exchange: %v", err)
			return
		}
	case ServerHelloDone:
		preMasterSecret, clientKeyExchange, err := c.pendingReadState.KeyAgreement.GenerateClientKeyExchange()
		if err != nil {
			log.Printf("Error while generating client key exchange: %v", err)
			return
		}
		c.sendClientKeyExchange(clientKeyExchange)
		masterSecret, clientMAC, serverMAC, clientKey, serverKey :=
			keysFromPreMasterSecret(preMasterSecret, c.pendingReadState.ClientRandom.Bytes(), c.pendingWriteState.ServerRandom.Bytes(),
				c.pendingReadState.CipherSuite.macLen, c.pendingReadState.keyLen)
		c.pendingWriteState.Cipher = c.pendingWriteState.CipherSuite.cipher(clientKey)
		c.pendingWriteState.Mac = c.pendingWriteState.CipherSuite.mac(clientMAC)
		c.sendChangeCipherSpec()
		c.currentWriteState = c.pendingWriteState
		c.pendingWriteState = SecurityParameters{}

		finishedMessage := new(HandshakeFinished)
		finishedMessage.VerifyData = c.finishedHash.clientSum(masterSecret)
		c.sendFinished(finishedMessage)
		_, _, _ = masterSecret, serverMAC, serverKey
		//TODO
	default:
	}
}

func (c *Conn) sendClientHello() error {
	clientHello := HandshakeClientHello{
		ClientVersion: DTLS_10,
		Random:        c.pendingWriteState.ClientRandom,
		SessionID:     c.sessionID,
		Cookie:        c.cookie,
		CipherSuites:  CipherSuites,
		CompressionMethods: []CompressionMethod{
			CompressionNone,
		},
	}
	clientHelloBytes := clientHello.Bytes()
	handshake := Handshake{
		MsgType:        ClientHello,
		Length:         uint32(len(clientHelloBytes)),
		MessageSeq:     c.handshakeSequenceNumber,
		FragmentOffset: 0,
		FragmentLength: uint32(len(clientHelloBytes)),
		Payload:        clientHello,
	}
	handshakeBytes := handshake.Bytes()
	c.finishedHash = newFinishedHash()
	c.finishedHash.Write(handshake.VerifyBytes())
	log.Printf("Writing %s to finished hash", handshake.MsgType)
	record := Record{
		Type:           TypeHandshake,
		Version:        DTLS_10,
		Epoch:          c.epoch,
		SequenceNumber: c.sequenceNumber,
		Length:         uint16(len(handshakeBytes)),
		Payload:        handshake,
	}
	c.handshakeSequenceNumber += 1
	c.sequenceNumber += 1
	return c.SendRecord(record)
}

func (c *Conn) sendClientKeyExchange(handshakeMessage ToBytes) error {
	handshakeMessageBytes := handshakeMessage.Bytes()
	handshake := Handshake{
		MsgType:        ClientKeyExchange,
		Length:         uint32(len(handshakeMessageBytes)),
		MessageSeq:     c.handshakeSequenceNumber,
		FragmentOffset: 0,
		FragmentLength: uint32(len(handshakeMessageBytes)),
		Payload:        handshakeMessage,
	}
	handshakeBytes := handshake.Bytes()
	c.finishedHash.Write(handshake.VerifyBytes())
	log.Printf("Writing %s to finished hash", handshake.MsgType)
	record := Record{
		Type:           TypeHandshake,
		Version:        DTLS_10,
		Epoch:          c.epoch,
		SequenceNumber: c.sequenceNumber,
		Length:         uint16(len(handshakeBytes)),
		Payload:        handshake,
	}
	c.handshakeSequenceNumber += 1
	c.sequenceNumber += 1
	return c.SendRecord(record)
}

func (c *Conn) sendFinished(message ToBytes) error {
	messageBytes := message.Bytes()
	handshake := Handshake{
		MsgType:        Finished,
		Length:         uint32(len(messageBytes)),
		MessageSeq:     c.handshakeSequenceNumber,
		FragmentOffset: 0,
		FragmentLength: uint32(len(messageBytes)),
		Payload:        message,
	}
	handshakeBytes := handshake.Bytes()
	record := Record{
		Type:           TypeHandshake,
		Version:        DTLS_10,
		Epoch:          c.epoch,
		SequenceNumber: c.sequenceNumber,
		Length:         uint16(len(handshakeBytes)),
		Payload:        handshake,
	}
	c.handshakeSequenceNumber += 1
	c.sequenceNumber += 1
	return c.SendRecord(record)
}

func (c *Conn) sendChangeCipherSpec() error {
	record := Record{
		Type:           TypeChangeCipherSpec,
		Version:        DTLS_10,
		Epoch:          c.epoch,
		SequenceNumber: c.sequenceNumber,
		Length:         1,
		Payload:        ChangeCipherSpec{1},
	}
	c.sequenceNumber += 1
	c.epoch += 1
	return c.SendRecord(record)
}
