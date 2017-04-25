package dtls

import (
	"fmt"
	"log"
	"os"
)

type handshakeContext interface {
	beginHandshake()
	continueHandshake(*handshake) (bool, error)
}

type baseHandshakeContext struct {
	*Conn

	isServer                  bool
	nextReceiveSequenceNumber uint16
	sequenceNumber            uint16
	currentFlight             int
	sessionID                 []byte
	cookie                    []byte
	cipherSuite               cipherSuite
	clientRandom              random
	serverRandom              random
	keyAgreement              keyAgreement
	masterSecret              []byte
	finishedHash              finishedHash

	//We omit the pre-flight, i.e. HelloVerify because otherwise we would need to keep state
	//defeating the purpose of HelloVerify
	//Flight 1
	clientHello *handshake

	//Flight 2
	serverHello        *handshake
	serverCertificate  *handshake
	serverKeyExchange  *handshake
	certificateRequest *handshake
	serverHelloDone    *handshake

	//Flight 3
	clientCertificate *handshake
	clientKeyExchange *handshake
	certificateVerify *handshake
	clientFinished    *handshake

	//Flight 4
	serverFinished *handshake

	handshakeMessageBuffer map[uint16]*handshakeFragmentList
}

func (hc *baseHandshakeContext) receiveMessage(message *handshake) {
	if message.MessageSeq < hc.nextReceiveSequenceNumber {
		log.Printf("Received handshake message with lower sequence number than next expected")
		return
	}
	if message.MessageSeq == hc.nextReceiveSequenceNumber &&
		message.FragmentOffset == 0 &&
		message.FragmentLength == message.Length {
		hc.storeMessage(message)
		hc.nextReceiveSequenceNumber += 1
	}
	if hfl, ok := hc.handshakeMessageBuffer[message.MessageSeq]; ok {
		hfl.InsertFragment(message)
	} else {
		hc.handshakeMessageBuffer[message.MessageSeq] = newHandshakeFragmentList(message)
	}
	hc.maybeReceiveNextBufferedMessage()
}

func (hc *baseHandshakeContext) maybeReceiveNextBufferedMessage() {
	for {
		hfl, ok := hc.handshakeMessageBuffer[hc.nextReceiveSequenceNumber]
		if !ok {
			return
		}
		if !hfl.IsComplete() {
			return
		}
		hc.storeMessage(hfl.GetCompleteHandshake())
		delete(hc.handshakeMessageBuffer, hc.nextReceiveSequenceNumber)
		hc.nextReceiveSequenceNumber += 1
	}
}

func (hc *baseHandshakeContext) storeMessage(message *handshake) {
	if hc.currentFlight == 1 && message.MsgType == clientHello {
		hc.clientHello = message
		return
		//TODO: handle out of order handshake messages?
	}
	if hc.currentFlight == 2 {
		switch message.MsgType {
		case serverHello:
			hc.serverHello = message
		case certificate:
			hc.serverCertificate = message
		case serverKeyExchange:
			hc.serverKeyExchange = message
		case certificateRequest:
			hc.certificateRequest = message
		case serverHelloDone:
			hc.serverHelloDone = message
		default:
			log.Printf("Unable to store received handshake message!")
			//TODO: how do we handle invalid handshake messages?
		}
		return
	}
	if hc.currentFlight == 3 {
		switch message.MsgType {
		case certificate:
			hc.clientCertificate = message
		case clientKeyExchange:
			hc.clientKeyExchange = message
		case certificateVerify:
			hc.certificateVerify = message
		case finished:
			hc.clientFinished = message
		default:
			log.Printf("Unable to store received handshake message!")
			//TODO: how do we handle invalid handshake messages?
		}
		return
	}
	if hc.currentFlight == 4 && message.MsgType == finished {
		hc.serverFinished = message
		//TODO: handle out of order handshake messages?
		return
	}
	log.Printf("Unable to store received handshake message!")
}

func (hc *baseHandshakeContext) buildNextHandshakeMessage(typ handshakeType, handshakeMessage []byte) *handshake {
	hdshk := &handshake{
		MsgType:        typ,
		Length:         uint32(len(handshakeMessage)),
		MessageSeq:     hc.sequenceNumber,
		FragmentOffset: 0,
		FragmentLength: uint32(len(handshakeMessage)),
		Fragment:       handshakeMessage,
	}
	hc.sequenceNumber += 1
	return hdshk
}

func (hc *baseHandshakeContext) sendHandshakeMessage(message *handshake) {
	hc.Conn.sendRecord(typeHandshake, message.Bytes())
}

func logMasterSecret(clientRandom, masterSecret []byte) {
	f, err := os.OpenFile("/home/maufl/.dtls-secrets", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Unable to open log file for DTLS master secret: %s", err)
		return
	}
	defer f.Close()
	if _, err = f.WriteString(fmt.Sprintf("CLIENT_RANDOM %x %x\n", clientRandom, masterSecret)); err != nil {
		log.Printf("Unable to write master secret to log file: %s", err)
	}
}
